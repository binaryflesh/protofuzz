"""The entry points to the protofuzz module.

Usage:

    >>> message_fuzzers = protofuzz.from_description_string('''
    ...     message Address {
    ...      required int32 house = 1;
    ...      required string street = 2;
    ...     }
    ... ''')
    >>> for fuzzer in message_fuzzers:
    ...     for obj in fuzzer.permute():
    ...         print("Generated object: {}".format(obj))
    ...
    Generated object: house: -1
    street: "!"

    Generated object: house: 0
    street: "!"

    Generated object: house: 256
    street: "!"

     (etc)

"""

# FIXME: Package containing module 'google' is not listed in project requirements
from google.protobuf import descriptor
from google.protobuf import message
from google.protobuf.internal import containers

from protofuzz import pbimport, gen, values

__all__ = ['ProtobufGenerator', 'from_file', 'from_description_string', 'from_protobuf_class']


def _int_generator(_descriptor, bitwidth, unsigned):
    vals = list(values.get_integers(bitwidth, unsigned))
    return gen.IterValueGenerator(_descriptor.name, vals)


def _string_generator(_descriptor, max_length=0, limit=0):
    vals = list(values.get_strings(max_length, limit))
    return gen.IterValueGenerator(_descriptor.name, vals)


def _bytes_generator(_descriptor, max_length=0, limit=0):
    strs = values.get_strings(max_length, limit)
    vals = [bytes(_, 'utf-8') for _ in strs]
    return gen.IterValueGenerator(_descriptor.name, vals)


def _float_generator(_descriptor, bitwidth):
    return gen.IterValueGenerator(_descriptor.name, values.get_floats(bitwidth))


def _enum_generator(_descriptor):
    vals = _descriptor.enum_type.values_by_number.keys()
    return gen.IterValueGenerator(_descriptor.name, vals)


def _prototype_to_generator(_descriptor, cls):
    """Return map of descriptor to a protofuzz generator."""
    _fd = descriptor.FieldDescriptor

    ints32 = [_fd.TYPE_INT32, _fd.TYPE_UINT32, _fd.TYPE_FIXED32, _fd.TYPE_SFIXED32, _fd.TYPE_SINT32]
    ints64 = [_fd.TYPE_INT64, _fd.TYPE_UINT64, _fd.TYPE_FIXED64, _fd.TYPE_SFIXED64, _fd.TYPE_SINT64]
    ints_signed = [_fd.TYPE_INT32, _fd.TYPE_SFIXED32, _fd.TYPE_SINT32, _fd.TYPE_INT64, _fd.TYPE_SFIXED64,
                   _fd.TYPE_SINT64]

    if _descriptor.type in ints32 + ints64:
        bitwidth = [32, 64][_descriptor.type in ints64]
        unsigned = _descriptor.type not in ints_signed
        generator = _int_generator(_descriptor, bitwidth, unsigned)
    elif _descriptor.type == _fd.TYPE_DOUBLE:
        generator = _float_generator(_descriptor, 64)
    elif _descriptor.type == _fd.TYPE_FLOAT:
        generator = _float_generator(_descriptor, 32)
    elif _descriptor.type == _fd.TYPE_STRING:
        generator = _string_generator(_descriptor)
    elif _descriptor.type == _fd.TYPE_BYTES:
        generator = _bytes_generator(_descriptor)
    elif _descriptor.type == _fd.TYPE_BOOL:
        generator = gen.IterValueGenerator(_descriptor.name, [True, False])
    elif _descriptor.type == _fd.TYPE_ENUM:
        generator = _enum_generator(_descriptor)
    elif _descriptor.type == _fd.TYPE_MESSAGE:
        generator = descriptor_to_generator(_descriptor.message_type, cls)
        generator.set_name(_descriptor.name)
    else:
        raise RuntimeError("type {} unsupported".format(_descriptor.type))

    return generator


def descriptor_to_generator(cls_descriptor, cls, limit=0):
    """Convert protobuf descriptor to a protofuzz generator for same type."""
    generators = []
    for _descriptor in cls_descriptor.fields_by_name.values():
        generator = _prototype_to_generator(_descriptor, cls)

        if not limit == 0:
            generator.set_limit(limit)

        generators.append(generator)

    obj = cls(cls_descriptor.name, *generators)
    return obj


def _assign_to_field(obj, name, val):
    """Return map of arbitrary value to a protobuf field."""
    target = getattr(obj, name)

    if isinstance(target, containers.RepeatedScalarFieldContainer):
        target.append(val)
    elif isinstance(target, containers.RepeatedCompositeFieldContainer):
        target = target.add()
        target.CopyFrom(val)
    elif isinstance(target, (int, float, bool, str, bytes)):
        setattr(obj, name, val)
    elif isinstance(target, message.Message):
        target.CopyFrom(val)
    else:
        raise RuntimeError("Unsupported type: {}".format(type(target)))


def _fields_to_object(_descriptor, fields):
    """Convert descriptor and a set of fields to a Protobuf instance."""
    # pylint: disable=protected-access
    obj = _descriptor._concrete_class()

    for name, value in fields:
        if isinstance(value, tuple):
            subtype = _descriptor.fields_by_name[name].message_type
            value = _fields_to_object(subtype, value)
        _assign_to_field(obj, name, value)

    return obj


class ProtobufGenerator(object):
    """A "fuzzing strategy" class that is associated with a Protobuf class.

    Currently, two strategies are supported:

     - permute()
        Generate permutations of fuzzed values for the fields.

     - linear()
        Generate fuzzed instances in lock-step (this is equivalent to running zip(*fields).

    """

    def __init__(self, _descriptor):
        """Protobufgenerator constructor."""
        self._descriptor = _descriptor
        self._dependencies = []

    def _iteration_helper(self, iter_class, limit):
        generator = descriptor_to_generator(self._descriptor, iter_class)

        if limit:
            generator.set_limit(limit)

        # Create dependencies before beginning generation
        for args in self._dependencies:
            generator.make_dependent(*args)

        for fields in generator:
            yield _fields_to_object(self._descriptor, fields)

    def add_dependency(self, source, target, action):
        """Create a dependency between fields source and target via callable action.

        >>> permuter = protofuzz.from_description_string('''
        ...   message Address {
        ...       required uint32 one = 1;
        ...       required uint32 two = 2;
        ...   }''')['Address']
        >>> permuter.add_dependency('one', 'two', lambda val: max(0, val - 1))
        >>> for obj in permuter.linear():
        ...   print("obj = {}".format(obj))
        ...
        obj = one: 0
        two: 1

        obj = one: 256
        two: 257

        obj = one: 4096
        two: 4097

        obj = one: 1073741823
        two: 1073741824

        """
        self._dependencies.append((source, target, action))

    def permute(self, limit=0):
        """Return a fuzzer that permutes all the fields with fuzzed values."""
        return self._iteration_helper(gen.Product, limit)

    def linear(self, limit=0):
        """Return a fuzzer that emulates "zip" behavior."""
        return self._iteration_helper(gen.Zip, limit)


def _module_to_generators(pb_module):
    """Convert protobuf module to dict of generators.

    This is typically used with modules that contain multiple type definitions.

    """
    if not pb_module:
        return None
    message_types = pb_module.DESCRIPTOR.message_types_by_name
    return {k: ProtobufGenerator(v) for k, v in message_types.items()}


def from_file(protobuf_file):
    """Return dict of generators from a path to a .proto file.

    Args:
        protobuf_file(str) -- The path to the .proto file.

    Returns:
        A dict indexed by message name of ProtobufGenerator objects.
        These can be used to create inter-field dependencies or to generate messages.

    Raises:
        BadProtobuf: If the .proto file is incorrectly formatted or named.
        ProtocNotFound: If the protoc compiler was not found on $PATH.

    """
    module = pbimport.from_file(protobuf_file)
    return _module_to_generators(module)


def from_description_string(protobuf_desc):
    """Return dict of generators from a string representation of the .proto file.

    Args:
        protobuf_desc(str) -- The description of protobuf messages; contents of
        what would usually go into a .proto file.

    Returns:
        A dict indexed by message name of ProtobufGenerator objects. These can
        be used to create inter-field dependencies or to generate messages.

    Raises:
        ProtocNotFound: If the protoc compiler was not found on $PATH.

    """
    module = pbimport.from_string(protobuf_desc)
    return _module_to_generators(module)


def from_protobuf_class(protobuf_class):
    """Return generator for an already-loaded Protobuf class.

    Args:
        protobuf_class(Message) -- A class object  created from Protobuf-
            generated code.

    Returns:
        A ProtobufGenerator instance that can be used to create inter-field
            dependencies or to generate messages.

    """
    return ProtobufGenerator(protobuf_class.DESCRIPTOR)
