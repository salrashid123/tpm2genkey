// FROM:  https://github.com/google/go-tpm

// Package tpm2 provides 1:1 mapping to TPM 2.0 APIs.
package util

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"reflect"
	"strconv"
	"strings"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

const (
	// Chosen based on MAX_DIGEST_BUFFER, the length of the longest
	// reasonable list returned by the reference implementation.
	// The maxListLength must be greater than MAX_CONTEXT_SIZE = 1344,
	// in order to allow for the unmarshalling of Context.
	maxListLength uint32 = 4096
)

func isMarshalledByReflection(v reflect.Value) bool {
	var mbr marshallableByReflection
	if v.Type().AssignableTo(reflect.TypeOf(&mbr).Elem()) {
		return true
	}
	// basic types are also marshalled by reflection, as are empty structs
	switch v.Kind() {
	case reflect.Bool, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64, reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Array, reflect.Slice, reflect.Ptr:
		return true
	case reflect.Struct:
		if v.NumField() == 0 {
			return true
		}
	}
	return false
}

// marshal will serialize the given value, appending onto the given buffer.
// Returns an error if the value is not marshallable.
func marshal(buf *bytes.Buffer, v reflect.Value) error {
	// If the type is not marshalled by reflection, try to call the custom marshal method.
	if !isMarshalledByReflection(v) {
		u, ok := v.Interface().(Marshallable)
		if ok {
			u.marshal(buf)
			return nil
		}
		if v.CanAddr() {
			// Maybe we got an addressable value whose pointer implements Marshallable
			pu, ok := v.Addr().Interface().(Marshallable)
			if ok {
				pu.marshal(buf)
				return nil
			}
		}
		//return fmt.Errorf("can't marshal: type %v does not implement Marshallable or marshallableByReflection", v.Type().Name())
	}

	// Otherwise, use reflection.
	switch v.Kind() {
	case reflect.Bool, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64, reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return marshalNumeric(buf, v)
	case reflect.Array, reflect.Slice:
		return marshalArray(buf, v)
	case reflect.Struct:
		return marshalStruct(buf, v)
	case reflect.Ptr:
		return marshal(buf, v.Elem())
	case reflect.Interface:
		// Special case: there are very few TPM types which, for TPM spec
		// backwards-compatibility reasons, are implemented as Go interfaces
		// so that callers can ergonomically satisfy cases where the TPM spec
		// allows a parameter to literally be one of a couple of types.
		// In a few of these cases, we want the caller to be able to sensibly
		// omit the data, and fill in reasonable defaults.
		// These cases are enumerated here.
		if v.IsNil() {
			switch v.Type().Name() {
			case "TPMUSensitiveCreate":
				return marshal(buf, reflect.ValueOf(tpm2.TPM2BSensitiveData{}))
			default:
				return fmt.Errorf("missing required value for %v interface", v.Type().Name())
			}
		}
		return marshal(buf, v.Elem())
	default:
		return fmt.Errorf("not marshallable: %#v", v)
	}
}

// marshalOptional will serialize the given value, appending onto the given
// buffer.
// Special case: Part 3 specifies some input/output
// parameters as "optional", which means that they are
// sized fields that can be zero-length, even if the
// enclosed type has no legal empty serialization.
// When nil, marshal the zero size.
// Returns an error if the value is not marshallable.
func marshalOptional(buf *bytes.Buffer, v reflect.Value) error {
	if v.Kind() == reflect.Ptr && v.IsNil() {
		return marshalArray(buf, reflect.ValueOf([2]byte{}))
	}
	return marshal(buf, v)
}

func marshalNumeric(buf *bytes.Buffer, v reflect.Value) error {
	return binary.Write(buf, binary.BigEndian, v.Interface())
}

func marshalArray(buf *bytes.Buffer, v reflect.Value) error {
	for i := 0; i < v.Len(); i++ {
		if err := marshal(buf, v.Index(i)); err != nil {
			return fmt.Errorf("marshalling element %d of %v: %v", i, v.Type(), err)
		}
	}
	return nil
}

// Marshals the members of the struct, handling sized and bitwise fields.
func marshalStruct(buf *bytes.Buffer, v reflect.Value) error {
	// Check if this is a bitwise-defined structure. This requires all the
	// members to be bitwise-defined.
	numBitwise := 0
	numChecked := 0
	for i := 0; i < v.NumField(); i++ {
		// Ignore embedded Bitfield hints.
		if !v.Type().Field(i).IsExported() {
			//if _, isBitfield := v.Field(i).Interface().(TPMABitfield); isBitfield {
			continue
		}
		thisBitwise := hasTag(v.Type().Field(i), "bit")
		if thisBitwise {
			numBitwise++
			if hasTag(v.Type().Field(i), "sized") || hasTag(v.Type().Field(i), "sized8") {
				return fmt.Errorf("struct '%v' field '%v' is both bitwise and sized",
					v.Type().Name(), v.Type().Field(i).Name)
			}
			if hasTag(v.Type().Field(i), "tag") {
				return fmt.Errorf("struct '%v' field '%v' is both bitwise and a tagged union",
					v.Type().Name(), v.Type().Field(i).Name)
			}
		}
		numChecked++
	}
	if numBitwise != numChecked && numBitwise != 0 {
		return fmt.Errorf("struct '%v' has mixture of bitwise and non-bitwise members", v.Type().Name())
	}
	if numBitwise > 0 {
		return marshalBitwise(buf, v)
	}
	// Make a pass to create a map of tag values
	// UInt64-valued fields with values greater than MaxInt64 cannot be
	// selectors.
	possibleSelectors := make(map[string]int64)
	for i := 0; i < v.NumField(); i++ {
		// Special case: Treat a zero-valued nullable field as
		// TPMAlgNull for union selection.
		// This allows callers to omit uninteresting scheme structures.
		if v.Field(i).IsZero() && hasTag(v.Type().Field(i), "nullable") {
			possibleSelectors[v.Type().Field(i).Name] = int64(tpm2.TPMAlgNull)
			continue
		}
		switch v.Field(i).Kind() {
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			possibleSelectors[v.Type().Field(i).Name] = v.Field(i).Int()
		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			val := v.Field(i).Uint()
			if val <= math.MaxInt64 {
				possibleSelectors[v.Type().Field(i).Name] = int64(val)
			}
		}
	}
	for i := 0; i < v.NumField(); i++ {
		if hasTag(v.Type().Field(i), "skip") {
			continue
		}
		list := hasTag(v.Type().Field(i), "list")
		sized := hasTag(v.Type().Field(i), "sized")
		sized8 := hasTag(v.Type().Field(i), "sized8")
		tag, _ := tag(v.Type().Field(i), "tag")
		// Serialize to a temporary buffer, in case we need to size it
		// (Better to simplify this complex reflection-based marshalling
		// code than to save some unnecessary copying before talking to
		// a low-speed device like a TPM)
		var res bytes.Buffer
		if list {
			binary.Write(&res, binary.BigEndian, uint32(v.Field(i).Len()))
		}
		if tag != "" {
			// Check that the tagged value was present (and numeric
			// and smaller than MaxInt64)
			tagValue, ok := possibleSelectors[tag]
			// Don't marshal anything if the tag value was TPM_ALG_NULL
			if tagValue == int64(tpm2.TPMAlgNull) {
				continue
			}
			if !ok {
				return fmt.Errorf("union tag '%v' for member '%v' of struct '%v' did not reference "+
					"a numeric field of int64-compatible value",
					tag, v.Type().Field(i).Name, v.Type().Name())
			}
			if u, ok := v.Field(i).Interface().(marshallableWithHint); ok {
				v, err := u.get(tagValue)
				if err != nil {
					return err
				}
				if err := marshal(buf, v); err != nil {
					return err
				}
			}
		} else if v.Field(i).IsZero() && v.Field(i).Kind() == reflect.Uint32 && hasTag(v.Type().Field(i), "nullable") {
			// Special case: Anything with the same underlying type
			// as TPMHandle's zero value is TPM_RH_NULL.
			// This allows callers to omit uninteresting handles
			// instead of specifying them as TPM_RH_NULL.
			if err := binary.Write(&res, binary.BigEndian, uint32(tpm2.TPMRHNull)); err != nil {
				return err
			}
		} else if v.Field(i).IsZero() && v.Field(i).Kind() == reflect.Uint16 && hasTag(v.Type().Field(i), "nullable") {
			// Special case: Anything with the same underlying type
			// as TPMAlg's zero value is TPM_ALG_NULL.
			// This allows callers to omit uninteresting
			// algorithms/schemes instead of specifying them as
			// TPM_ALG_NULL.
			if err := binary.Write(&res, binary.BigEndian, uint16(tpm2.TPMAlgNull)); err != nil {
				return err
			}
		} else if hasTag(v.Type().Field(i), "optional") {
			if err := marshalOptional(&res, v.Field(i)); err != nil {
				return err
			}
		} else {
			if err := marshal(&res, v.Field(i)); err != nil {
				return err
			}
		}
		if sized {
			if err := binary.Write(buf, binary.BigEndian, uint16(res.Len())); err != nil {
				return err
			}
		}
		if sized8 {
			if err := binary.Write(buf, binary.BigEndian, uint8(res.Len())); err != nil {
				return err
			}
		}
		buf.Write(res.Bytes())
	}
	return nil
}

// Marshals a bitwise-defined struct.
func marshalBitwise(buf *bytes.Buffer, v reflect.Value) error {
	bg, ok := v.Interface().(tpm2.BitGetter)
	if !ok {
		return fmt.Errorf("'%v' was not a BitGetter", v.Type().Name())
	}
	bitArray := make([]bool, bg.Length())
	// Marshal the defined fields
	for i := 0; i < v.NumField(); i++ {
		if !v.Type().Field(i).IsExported() {
			continue
		}
		high, low, _ := rangeTag(v.Type().Field(i), "bit")
		var buf bytes.Buffer
		if err := marshal(&buf, v.Field(i)); err != nil {
			return err
		}
		b := buf.Bytes()
		for i := 0; i <= (high - low); i++ {
			bitArray[low+i] = ((b[len(b)-i/8-1] >> (i % 8)) & 1) == 1
		}
	}
	// Also marshal the reserved values
	for i := 0; i < len(bitArray); i++ {
		if bg.GetReservedBit(i) {
			bitArray[i] = true
		}
	}
	result := make([]byte, len(bitArray)/8)
	for i, bit := range bitArray {
		if bit {
			result[len(result)-(i/8)-1] |= (1 << (i % 8))
		}
	}
	buf.Write(result)
	return nil
}

// unmarshal will deserialize the given value from the given buffer.
// Returns an error if the buffer does not contain enough data to satisfy the
// type.
func unmarshal(buf *bytes.Buffer, v reflect.Value) error {
	// If the type is not marshalled by reflection, try to call the custom unmarshal method.
	if !isMarshalledByReflection(v) {
		if u, ok := v.Addr().Interface().(Unmarshallable); ok {
			return u.unmarshal(buf)
		}
		//return fmt.Errorf("can't unmarshal: type %v does not implement Unmarshallable or marshallableByReflection", v.Type().Name())
	}

	switch v.Kind() {
	case reflect.Bool, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64, reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		if err := unmarshalNumeric(buf, v); err != nil {
			return err
		}
	case reflect.Slice:
		var length uint32
		// special case for byte slices: just read the entire
		// rest of the buffer
		if v.Type().Elem().Kind() == reflect.Uint8 {
			length = uint32(buf.Len())
		} else {
			err := unmarshalNumeric(buf, reflect.ValueOf(&length).Elem())
			if err != nil {
				return fmt.Errorf("deserializing size for field of type '%v': %w", v.Type(), err)
			}
		}
		if length > uint32(math.MaxInt32) || length > maxListLength {
			return fmt.Errorf("could not deserialize slice of length %v", length)
		}
		// Go's reflect library doesn't allow increasing the
		// capacity of an existing slice.
		// Since we can't be sure that the capacity of the
		// passed-in value was enough, allocate
		// a new temporary one of the correct length, unmarshal
		// to it, and swap it in.
		tmp := reflect.MakeSlice(v.Type(), int(length), int(length))
		if err := unmarshalArray(buf, tmp); err != nil {
			return err
		}
		v.Set(tmp)
		return nil
	case reflect.Array:
		return unmarshalArray(buf, v)
	case reflect.Struct:
		return unmarshalStruct(buf, v)
	case reflect.Ptr:
		return unmarshal(buf, v.Elem())
	default:
		return fmt.Errorf("not unmarshallable: %v", v.Type())
	}
	return nil
}

func unmarshalNumeric(buf *bytes.Buffer, v reflect.Value) error {
	return binary.Read(buf, binary.BigEndian, v.Addr().Interface())
}

// For slices, the slice's length must already be set to the expected amount of
// data.
func unmarshalArray(buf *bytes.Buffer, v reflect.Value) error {
	for i := 0; i < v.Len(); i++ {
		if err := unmarshal(buf, v.Index(i)); err != nil {
			return fmt.Errorf("deserializing slice/array index %v: %w", i, err)
		}
	}
	return nil
}

func unmarshalStruct(buf *bytes.Buffer, v reflect.Value) error {
	// Check if this is a bitwise-defined structure. This requires all the
	// exported members to be bitwise-defined.
	numBitwise := 0
	numChecked := 0
	for i := 0; i < v.NumField(); i++ {
		// Ignore embedded Bitfield hints.
		// Ignore embedded Bitfield hints.
		if !v.Type().Field(i).IsExported() {
			//if _, isBitfield := v.Field(i).Interface().(TPMABitfield); isBitfield {
			continue
		}
		thisBitwise := hasTag(v.Type().Field(i), "bit")
		if thisBitwise {
			numBitwise++
			if hasTag(v.Type().Field(i), "sized") {
				return fmt.Errorf("struct '%v' field '%v' is both bitwise and sized",
					v.Type().Name(), v.Type().Field(i).Name)
			}
			if hasTag(v.Type().Field(i), "tag") {
				return fmt.Errorf("struct '%v' field '%v' is both bitwise and a tagged union",
					v.Type().Name(), v.Type().Field(i).Name)
			}
		}
		numChecked++
	}
	if numBitwise != numChecked && numBitwise != 0 {
		return fmt.Errorf("struct '%v' has mixture of bitwise and non-bitwise members", v.Type().Name())
	}
	if numBitwise > 0 {
		return unmarshalBitwise(buf, v)
	}
	for i := 0; i < v.NumField(); i++ {
		if hasTag(v.Type().Field(i), "skip") {
			continue
		}
		list := hasTag(v.Type().Field(i), "list")
		if list && (v.Field(i).Kind() != reflect.Slice) {
			return fmt.Errorf("field '%v' of struct '%v' had the 'list' tag but was not a slice",
				v.Type().Field(i).Name, v.Type().Name())
		}
		// Slices of anything but byte/uint8 must have the 'list' tag.
		if !list && (v.Field(i).Kind() == reflect.Slice) && (v.Type().Field(i).Type.Elem().Kind() != reflect.Uint8) {
			return fmt.Errorf("field '%v' of struct '%v' was a slice of non-byte but did not have the 'list' tag",
				v.Type().Field(i).Name, v.Type().Name())
		}
		if hasTag(v.Type().Field(i), "optional") {
			// Special case: Part 3 specifies some input/output
			// parameters as "optional", which means that they are
			// (2B-) sized fields that can be zero-length, even if the
			// enclosed type has no legal empty serialization.
			// When unmarshalling an optional field, test for zero size
			// and skip if empty.
			if buf.Len() < 2 {
				if binary.BigEndian.Uint16(buf.Bytes()) == 0 {
					// Advance the buffer past the zero size and skip to the
					// next field of the struct.
					buf.Next(2)
					continue
				}
				// If non-zero size, proceed to unmarshal the contents below.
			}
		}
		sized := hasTag(v.Type().Field(i), "sized")
		sized8 := hasTag(v.Type().Field(i), "sized8")
		// If sized, unmarshal a size field first, then restrict
		// unmarshalling to the given size
		bufToReadFrom := buf
		if sized {
			var expectedSize uint16
			binary.Read(buf, binary.BigEndian, &expectedSize)
			sizedBufArray := make([]byte, int(expectedSize))
			n, err := buf.Read(sizedBufArray)
			if n != int(expectedSize) {
				return fmt.Errorf("ran out of data reading sized parameter '%v' inside struct of type '%v'",
					v.Type().Field(i).Name, v.Type().Name())
			}
			if err != nil {
				return fmt.Errorf("error reading data for parameter '%v' inside struct of type '%v'",
					v.Type().Field(i).Name, v.Type().Name())
			}
			bufToReadFrom = bytes.NewBuffer(sizedBufArray)
		}
		if sized8 {
			var expectedSize uint8
			binary.Read(buf, binary.BigEndian, &expectedSize)
			sizedBufArray := make([]byte, int(expectedSize))
			n, err := buf.Read(sizedBufArray)
			if n != int(expectedSize) {
				return fmt.Errorf("ran out of data reading sized parameter '%v' inside struct of type '%v'",
					v.Type().Field(i).Name, v.Type().Name())
			}
			if err != nil {
				return fmt.Errorf("error reading data for parameter '%v' inside struct of type '%v'",
					v.Type().Field(i).Name, v.Type().Name())
			}
			bufToReadFrom = bytes.NewBuffer(sizedBufArray)
		}
		tag, _ := tag(v.Type().Field(i), "tag")
		if tag != "" {
			// Make a pass to create a map of tag values
			// UInt64-valued fields with values greater than
			// MaxInt64 cannot be selectors.
			possibleSelectors := make(map[string]int64)
			for j := 0; j < v.NumField(); j++ {
				switch v.Field(j).Kind() {
				case reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
					possibleSelectors[v.Type().Field(j).Name] = v.Field(j).Int()
				case reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
					val := v.Field(j).Uint()
					if val <= math.MaxInt64 {
						possibleSelectors[v.Type().Field(j).Name] = int64(val)
					}
				}
			}
			// Check that the tagged value was present (and numeric
			// and smaller than MaxInt64)
			tagValue, ok := possibleSelectors[tag]
			// Don't marshal anything if the tag value was TPM_ALG_NULL
			if tagValue == int64(tpm2.TPMAlgNull) {
				continue
			}
			if !ok {
				return fmt.Errorf("union tag '%v' for member '%v' of struct '%v' did not reference "+
					"a numeric field of in64-compatible value",
					tag, v.Type().Field(i).Name, v.Type().Name())
			}
			var uwh unmarshallableWithHint
			if v.Field(i).CanAddr() && v.Field(i).Addr().Type().AssignableTo(reflect.TypeOf(&uwh).Elem()) {
				u := v.Field(i).Addr().Interface().(unmarshallableWithHint)
				contents, err := u.create(tagValue)
				if err != nil {
					return fmt.Errorf("unmarshalling field %v of struct of type '%v', %w", i, v.Type(), err)
				}
				err = unmarshal(buf, contents)
				if err != nil {
					return fmt.Errorf("unmarshalling field %v of struct of type '%v', %w", i, v.Type(), err)
				}
			} else if v.Field(i).Type().AssignableTo(reflect.TypeOf(&uwh).Elem()) {
				u := v.Field(i).Interface().(unmarshallableWithHint)
				contents, err := u.create(tagValue)
				if err != nil {
					return fmt.Errorf("unmarshalling field %v of struct of type '%v', %w", i, v.Type(), err)
				}
				err = unmarshal(buf, contents)
				if err != nil {
					return fmt.Errorf("unmarshalling field %v of struct of type '%v', %w", i, v.Type(), err)
				}
			}
		} else {
			if err := unmarshal(bufToReadFrom, v.Field(i)); err != nil {
				return fmt.Errorf("unmarshalling field %v of struct of type '%v', %w", i, v.Type(), err)
			}
		}
		if sized || sized8 {
			if bufToReadFrom.Len() != 0 {
				return fmt.Errorf("extra data at the end of sized parameter '%v' inside struct of type '%v'",
					v.Type().Field(i).Name, v.Type().Name())
			}
		}
	}
	return nil
}

// Unmarshals a bitwise-defined struct.
func unmarshalBitwise(buf *bytes.Buffer, v reflect.Value) error {
	bs, ok := v.Addr().Interface().(tpm2.BitSetter)
	if !ok {
		return fmt.Errorf("'%v' was not a BitSetter", v.Addr().Type())
	}
	bitArray := make([]bool, bs.Length())
	// We will read big-endian, starting from the last byte and working our
	// way down.
	for i := len(bitArray)/8 - 1; i >= 0; i-- {
		b, err := buf.ReadByte()
		if err != nil {
			return fmt.Errorf("error %d bits into field '%v' of struct '%v': %w",
				i, v.Type().Field(i).Name, v.Type().Name(), err)
		}
		for j := 0; j < 8; j++ {
			bitArray[8*i+j] = (((b >> j) & 1) == 1)
		}
	}
	// Unmarshal the defined fields and clear the bits from the array as we
	// read them.
	for i := 0; i < v.NumField(); i++ {
		if !v.Type().Field(i).IsExported() {
			continue
		}
		high, low, _ := rangeTag(v.Type().Field(i), "bit")
		var val uint64
		for j := 0; j <= high-low; j++ {
			if bitArray[low+j] {
				val |= (1 << j)
			}
			bitArray[low+j] = false
		}
		if v.Field(i).Kind() == reflect.Bool {
			v.Field(i).SetBool((val & 1) == 1)
		} else {
			v.Field(i).SetUint(val)
		}
	}
	// Unmarshal the remaining uncleared bits as reserved bits.
	for i := 0; i < len(bitArray); i++ {
		bs.SetReservedBit(i, bitArray[i])
	}
	return nil
}

// Looks up the given gotpm tag on a field.
// Some tags are settable (with "="). For these, the value is the RHS.
// For all others, the value is the empty string.
func tag(t reflect.StructField, query string) (string, bool) {
	allTags, ok := t.Tag.Lookup("gotpm")
	if !ok {
		return "", false
	}
	tags := strings.Split(allTags, ",")
	for _, tag := range tags {
		// Split on the equals sign for settable tags.
		// If the split returns a slice of length 1, this is an
		//   un-settable tag or an empty tag (which we'll ignore).
		// If the split returns a slice of length 2, this is a settable
		//   tag.
		if tag == query {
			return "", true
		}
		if strings.HasPrefix(tag, query+"=") {
			assignment := strings.SplitN(tag, "=", 2)
			return assignment[1], true
		}
	}
	return "", false
}

// hasTag looks up to see if the type's gotpm-namespaced tag contains the
// given value.
// Returns false if there is no gotpm-namespaced tag on the type.
func hasTag(t reflect.StructField, query string) bool {
	_, ok := tag(t, query)
	return ok
}

// Returns the range on a tag like 4:3 or 4.
// If there is no colon, the low and high part of the range are equal.
func rangeTag(t reflect.StructField, query string) (int, int, bool) {
	val, ok := tag(t, query)
	if !ok {
		return 0, 0, false
	}
	vals := strings.Split(val, ":")
	high, err := strconv.Atoi(vals[0])
	if err != nil {
		return 0, 0, false
	}
	low := high
	if len(vals) > 1 {
		low, err = strconv.Atoi(vals[1])
		if err != nil {
			return 0, 0, false
		}
	}
	if low > high {
		low, high = high, low
	}
	return high, low, true
}

// taggedMembers will return a slice of all the members of the given
// structure that contain (or don't contain) the given tag in the "gotpm"
// namespace.
// Panics if v's Kind is not Struct.
func taggedMembers(v reflect.Value, tag string, invert bool) []reflect.Value {
	var result []reflect.Value
	t := v.Type()

	for i := 0; i < t.NumField(); i++ {
		// Add this one to the list if it has the tag and we're not
		// inverting, or if it doesn't have the tag and we are
		// inverting.
		if hasTag(t.Field(i), tag) != invert {
			result = append(result, v.Field(i))
		}
	}

	return result
}

// TODO: Extract the logic of "marshal the Nth field of some struct after the handles"
// For now, we duplicate some logic from marshalStruct here.
func marshalParameter[R any](buf *bytes.Buffer, cmd tpm2.Command[R, *R], i int) error {
	numHandles := len(taggedMembers(reflect.ValueOf(cmd), "handle", false))
	if numHandles+i >= reflect.TypeOf(cmd).NumField() {
		return fmt.Errorf("invalid parameter index %v", i)
	}
	parm := reflect.ValueOf(cmd).Field(numHandles + i)
	field := reflect.TypeOf(cmd).Field(numHandles + i)
	if hasTag(field, "optional") {
		return marshalOptional(buf, parm)
	} else if parm.IsZero() && parm.Kind() == reflect.Uint32 && hasTag(field, "nullable") {
		return marshal(buf, reflect.ValueOf(tpm2.TPMRHNull))
	} else if parm.IsZero() && parm.Kind() == reflect.Uint16 && hasTag(field, "nullable") {
		return marshal(buf, reflect.ValueOf(tpm2.TPMAlgNull))
	}

	return marshal(buf, parm)
}

// CPBytes (tpm2.Policy): Convert a TPM Policy to command bytes
func CPBytes[R any](cmd tpm2.Command[R, *R]) ([]byte, error) {

	if cmd.Command() == tpm2.TPMCCPolicySecret {
		v := reflect.ValueOf(cmd)
		y := v.Interface().(tpm2.PolicySecret)

		a := make([]byte, 4)
		hintHandle := y.AuthHandle.HandleValue()
		//hintHandle = 0
		binary.BigEndian.PutUint32(a, hintHandle) // TPMRHEndorsement TPMHandle = 0x4000000B

		b := make([]byte, 2)
		binary.BigEndian.PutUint16(b, uint16(len(y.AuthHandle.KnownName().Buffer)))
		var m []byte
		m = append(m, b...)
		m = append(m, y.AuthHandle.KnownName().Buffer...)

		var policySecretBytes []byte
		policySecretBytes = append(policySecretBytes, a...)
		policySecretBytes = append(policySecretBytes, m...)
		policySecretBytes = append(policySecretBytes, []byte(y.PolicyRef.Buffer)...)
		return policySecretBytes, nil
	}

	//  TPM2_PolicyAuthorize MUST be TPM2B_PUBLIC keySign, TPM2B_DIGEST policyRef, TPMT_SIGNATURE policySignature.
	if cmd.Command() == tpm2.TPMCCPolicyAuthorize {
		return nil, errors.New("Unimplemented; use CPBytesAuthorize()")
	}

	parms := taggedMembers(reflect.ValueOf(cmd), "handle", true)
	if len(parms) == 0 {
		return nil, nil
	}

	var firstParm bytes.Buffer
	if err := marshalParameter(&firstParm, cmd, 0); err != nil {
		return nil, err
	}
	firstParmBytes := firstParm.Bytes()

	var result bytes.Buffer
	result.Write(firstParmBytes)
	for i := 1; i < len(parms); i++ {
		if err := marshalParameter(&result, cmd, i); err != nil {
			return nil, err
		}
	}
	return result.Bytes(), nil
}

func CPBytesPolicyAuthorize(policyRefString string, signerTemplate tpm2.TPMTPublic, sig tpm2.TPMTSignature) ([]byte, error) {

	rsa_TPMTPublic_bytes := tpm2.Marshal(signerTemplate)
	rsa_TPM2BPublic := tpm2.BytesAs2B[tpm2.TPM2BPublic](rsa_TPMTPublic_bytes)
	rsa_TPM2BPublic_bytes := tpm2.Marshal(rsa_TPM2BPublic)

	policyRefDigestSegment := tpm2.Marshal(tpm2.TPM2BDigest{
		Buffer: []byte(policyRefString),
	})
	sig_bytes := tpm2.Marshal(sig)

	policyCommand := append(rsa_TPM2BPublic_bytes, policyRefDigestSegment...)
	policyCommand = append(policyCommand, sig_bytes...)
	return policyCommand, nil
}

// ReqParameters convert bytes to a TPM Policy
func ReqParameters(parms []byte, rspStruct any) error {

	if len(parms) < 2 {
		return nil
	}
	numHandles := len(taggedMembers(reflect.ValueOf(rspStruct).Elem(), "handle", false))

	buf := bytes.NewBuffer(parms)
	for i := numHandles; i < reflect.TypeOf(rspStruct).Elem().NumField(); i++ {
		parmsField := reflect.ValueOf(rspStruct).Elem().Field(i)
		if parmsField.Kind() == reflect.Ptr && hasTag(reflect.TypeOf(rspStruct).Elem().Field(i), "optional") {
			if binary.BigEndian.Uint16(buf.Bytes()) == 0 {
				buf.Next(2)
				continue
			}
		}
		if err := unmarshal(buf, parmsField); err != nil {
			return err
		}
	}
	return nil
}

func ReqParametersPolicySecret(parms []byte, rspStruct *tpm2.PolicySecret) (tpm2.PolicySecret, error) {

	var na tpm2.TPMHandle
	// v := reflect.ValueOf(rspStruct)

	hintBytes := parms[:4]
	hintInt32 := binary.BigEndian.Uint32(hintBytes)

	nameLengthBytes := parms[4 : 4+2]

	nameBytes := parms[4+2 : 4+2+binary.BigEndian.Uint16(nameLengthBytes)]
	nc, err := tpm2.Unmarshal[tpm2.TPM2BName](append(nameLengthBytes, nameBytes...))
	if err != nil {
		return tpm2.PolicySecret{}, err
	}
	nonceBytes := parms[4+2+binary.BigEndian.Uint16(nameLengthBytes):]

	if hintInt32 != 0 {
		if hex.EncodeToString(tpm2.HandleName(tpm2.TPMHandle(hintInt32)).Buffer) != hex.EncodeToString(nc.Buffer) {
			return tpm2.PolicySecret{}, fmt.Errorf("names do not match: %v", err)
		}
		na = tpm2.TPMHandle(hintInt32)
	} else {
		na = tpm2.TPMHandle(binary.BigEndian.Uint32(nc.Buffer))
	}

	r := tpm2.PolicySecret{
		AuthHandle: na, //tpm2.TPMHandle(hintInt32), // tpm2.TPMRHEndorsement,
		PolicyRef: tpm2.TPM2BNonce{
			Buffer: nonceBytes,
		},
		NonceTPM:      rspStruct.NonceTPM,
		PolicySession: rspStruct.PolicySession,
	}
	return r, nil
}

func ReqParametersPolicyAuthorize(rwr transport.TPM, parms []byte, approvedPolicy tpm2.TPM2BDigest, rspStruct *tpm2.PolicyAuthorize) (tpm2.PolicyAuthorize, error) {

	keyLengthBytes := parms[:2]
	tp, err := tpm2.Unmarshal[tpm2.TPM2BPublic](parms[:2+binary.BigEndian.Uint16(keyLengthBytes)])
	if err != nil {
		return tpm2.PolicyAuthorize{}, err
	}
	reGenKeyPublic, err := tp.Contents()
	if err != nil {
		return tpm2.PolicyAuthorize{}, err
	}

	l2, err := tpm2.LoadExternal{
		InPublic:  tpm2.New2B(*reGenKeyPublic),
		Hierarchy: tpm2.TPMRHOwner,
	}.Execute(rwr)
	if err != nil {
		return tpm2.PolicyAuthorize{}, err
	}
	defer func() {
		flush := tpm2.FlushContext{
			FlushHandle: l2.ObjectHandle,
		}
		_, err = flush.Execute(rwr)
	}()

	remainder := parms[2+binary.BigEndian.Uint16(keyLengthBytes):]
	//extract policyRefDigestSegment
	lenpolicyRefDigestSegment := remainder[:2]
	dda, err := tpm2.Unmarshal[tpm2.TPM2BDigest](remainder[:2+binary.BigEndian.Uint16(lenpolicyRefDigestSegment)])
	if err != nil {
		return tpm2.PolicyAuthorize{}, err
	}

	toDigest2 := append(approvedPolicy.Buffer, dda.Buffer...)
	msgHash2 := sha256.New()
	_, err = msgHash2.Write(toDigest2)
	if err != nil {
		return tpm2.PolicyAuthorize{}, err
	}
	msgHashpcrSum2 := msgHash2.Sum(nil)

	//extract TPMTSignature

	regenSig := remainder[2+binary.BigEndian.Uint16(lenpolicyRefDigestSegment):]

	tts, err := tpm2.Unmarshal[tpm2.TPMTSignature](regenSig)
	if err != nil {
		return tpm2.PolicyAuthorize{}, err
	}

	// now ready

	v, err := tpm2.VerifySignature{
		KeyHandle: l2.ObjectHandle,
		Digest: tpm2.TPM2BDigest{
			Buffer: msgHashpcrSum2,
		},
		Signature: *tts,
	}.Execute(rwr)
	if err != nil {
		return tpm2.PolicyAuthorize{}, err
	}

	r := tpm2.PolicyAuthorize{
		PolicySession:  rspStruct.PolicySession,
		ApprovedPolicy: approvedPolicy, // use the expected digest we want to sign
		KeySign:        l2.Name,
		PolicyRef:      *dda,
		CheckTicket:    v.Validation,
	}
	return r, nil
}
