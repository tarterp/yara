
.. _dotnet-module:

#############
dotnet module
#############

.. versionadded:: 3.6.0

The dotnet module allows you to create more fine-grained rules for .NET files by
using attributes and features of the .NET file format. Let's see some examples:

.. code-block:: yara

    import "dotnet"

    rule not_exactly_five_streams
    {
        condition:
            dotnet.number_of_streams != 5
    }

    rule blop_stream
    {
        condition:
            for any i in (0..dotnet.number_of_streams - 1):
                (dotnet.streams[i].name == "#Blop")
    }

Reference
---------

.. c:type:: is_dotnet
    
    verifies the version string contained in the metadata root is valid

.. c:type:: major_runtime_version

    The major version contained in the CLI header

.. c:type:: minor_runtime_version

    The major version contained in the CLI header

.. c:type:: Flags

    CLI header Runtime Flags contains the following values
    
    .. c:member:: CORHEADER_IL_ONLY           

    .. c:member:: CORHEADER_32_BIT_REQUIRED    

    .. c:member:: CORHEADER_IL_LIBRARY       

    .. c:member:: CORHEADER_STRONG_NAME_SIGNED 

    .. c:member:: CORHEADER_NATIVE_ENTRYPOINT

    .. c:member:: CORHEADER_TRACK_DEBUG_DATA

.. c:type:: entry_point

    If CORHEADER_NATIVE_ENTRYPOINT is set, EntryPointRVA represents an RVA 
    to a native entrypoint. If CORHEADER_NATIVE_ENTRYPOINT is not set, 
    EntryPointToken represents a managed entrypoint.

.. c:type:: version

    The version string contained in the metadata root.

    *Example: dotnet.version == "v2.0.50727"*

.. c:type:: module_name

    The name of the module.

    *Example: dotnet.module_name == "axs"*

.. c:type:: number_of_streams

    The number of streams in the file.

.. c:type:: streams

    A zero-based array of stream objects, one for each stream contained in the
    file. Individual streams can be accessed by using the [] operator. Each
    stream object has the following attributes:

    .. c:member:: name

        Stream name.

    .. c:member:: offset

        Stream offset.

    .. c:member:: size

        Stream size.

    *Example: dotnet.streams[0].name == "#~"*

.. c:type:: number_of_guids

    The number of GUIDs in the guids array.

.. c:type:: guids

    A zero-based array of strings, one for each GUID. Individual guids can be
    accessed by using the [] operator.

    *Example: dotnet.guids[0] == "99c08ffd-f378-a891-10ab-c02fe11be6ef"*

.. c:type:: number_of_resources

    The number of resources in the .NET file. These are different from normal PE
    resources.

.. c:type:: resources

    A zero-based array of resource objects, one for each resource the .NET file
    has.  Individual resources can be accessed by using the [] operator. Each
    resource object has the following attributes:

    .. c:member:: offset

        Offset for the resource data.

    .. c:member:: length

        Length of the resource data.

    .. c:member:: name

        Name of the resource (string).

    *Example: uint16be(dotnet.resources[0].offset) == 0x4d5a*

.. c:type:: assembly

    Object for .NET assembly information.

    .. c:member:: version

        An object with integer values representing version information for this
        assembly. Attributes are:

        ``major``
        ``minor``
        ``build_number``
        ``revision_number``

    .. c:member:: name

        String containing the assembly name.

    .. c:member:: culture

        String containing the culture (language/country/region) for this
        assembly.

    *Example: dotnet.assembly.name == "Keylogger"*

    *Example: dotnet.assembly.version.major == 7 and dotnet.assembly.version.minor == 0*

.. c:type:: number_of_modulerefs

    The number of module references in the .NET file.

.. c:type:: modulerefs

    A zero-based array of strings, one for each module reference the .NET file
    has.  Individual module references can be accessed by using the []
    operator.

    *Example: dotnet.modulerefs[0] == "kernel32"*

.. c:type:: typelib

    The typelib of the file.

.. c:type:: assembly_refs

    Object for .NET assembly reference information.

    .. c:member:: version

        An object with integer values representing version information for this
        assembly. Attributes are:

        ``major``
        ``minor``
        ``build_number``
        ``revision_number``

    .. c:member:: name

        String containing the assembly name.

    .. c:member:: public_key_or_token

        String containing the public key or token which identifies the author of
        this assembly.

.. c:type:: number_of_methods

    the number of methods in the file

.. c:type:: methods

    A zero-based array of methods associating operations with a type. Individual
    methods can be accessed by using the [] operator. Each method has the
    following attributes:

    .. c:member:: RVA

        A relative virtual address of the method

    .. c:member:: ImplFlags

        Integer representing method implementation attributes with one of the 
        following values:

        .. c:member:: METHOD_IMPL_FLAGS_CODE_TYPE_MASK
        
        .. c:member:: METHOD_IMPL_FLAGS_IL            
        
        .. c:member:: METHOD_IMPL_FLAGS_IS_NATIVE     
        
        .. c:member:: METHOD_IMPL_FLAGS_OPTIL         
        
        .. c:member:: METHOD_IMPL_FLAGS_RUNTIME       
        
        .. c:member:: METHOD_IMPL_FLAGS_MANAGED_MASK  
        
        .. c:member:: METHOD_IMPL_FLAGS_UNMANAGED     
        
        .. c:member:: METHOD_IMPL_FLAGS_MANAGED       
        
        .. c:member:: METHOD_IMPL_FLAGS_FORWARD_REF   
        
        .. c:member:: METHOD_IMPL_FLAGS_PRESERVE_SIG  
        
        .. c:member:: METHOD_IMPL_FLAGS_INTERNAL_CALL 
        
        .. c:member:: METHOD_IMPL_FLAGS_SYNCHRONIZED  
        
        .. c:member:: METHOD_IMPL_FLAGS_NO_INLINING   
        
        .. c:member:: METHOD_IMPL_FLAGS_NO_OPTIMIZATION

        *Example: dotnet.methods[0].ImplFlags & dotnet.METHOD_IMPL_FLAGS_IS_NATIVE*

    .. c:member:: Flags

        .. c:member:: METHOD_FLAGS_MEMBER_ACCESS_MASK

        .. c:member:: METHOD_FLAGS_COMPILER_CONTROLLED

        .. c:member:: METHOD_FLAGS_PRIVATE           

        .. c:member:: METHOD_FLAGS_FAM_AND_ASSEM     

        .. c:member:: METHOD_FLAGS_ASSEM             

        .. c:member:: METHOD_FLAGS_FAMILY            

        .. c:member:: METHOD_FLAGS_FAM_OR_ASSEM      

        .. c:member:: METHOD_FLAGS_PUBLIC            

        .. c:member:: METHOD_FLAGS_STATIC            

        .. c:member:: METHOD_FLAGS_FINAL             

        .. c:member:: METHOD_FLAGS_VIRTUAL           

        .. c:member:: METHOD_FLAGS_HIDE_BY_SIG       

        .. c:member:: METHOD_FLAGS_VTABLE_LAYOUT_MASK

        .. c:member:: METHOD_FLAGS_REUSE_SLOT        

        .. c:member:: METHOD_FLAGS_NEW_SLOT          

        .. c:member:: METHOD_FLAGS_STRICT            

        .. c:member:: METHOD_FLAGS_ABSTRACT          

        .. c:member:: METHOD_FLAGS_SPECIAL_NAME      

        .. c:member:: METHOD_FLAGS_PINVOKE_IMPL      

        .. c:member:: METHOD_FLAGS_UNMANAGED_EXPORT  

        .. c:member:: METHOD_FLAGS_RTS_SPECIAL_NAME  

        .. c:member:: METHOD_FLAGS_HAS_SECURITY      

        .. c:member:: METHOD_FLAGS_REQUIRE_SEC_OBJECT

        *Example: dotnet.methods[0].Flags & dotnet.METHOD_FLAGS_STATIC*

    .. c:member:: Name

        method name

        *Example: dotnet.methods[0].name == "Foo"*

.. c:type:: number_of_typerefs

    the number of type references in the file

.. c:type:: typerefs

    A zero based array of type references, logical descriptions of user-defined 
    types that are referenced in the current module. Individual typerefs can
    be access by using the [] operator. Each typeref has the following
    attributes:

    .. c:member:: Name

    *Example: dotnet.typerefs[0].Name == "Decoder"*

    .. c:member:: NameSpace

    *Example: dotnet.typerefs[0].Namespace == "System.Text"*

.. c:type:: number_of_user_strings

    The number of user strings in the file.

.. c:type:: user_strings

    An zero-based array of user strings, one for each stream contained in the
    file. Individual strings can be accessed by using the [] operator.

.. c:type:: number_of_field_offsets

    The number of fields in the field_offsets array.

.. c:type:: field_offsets

    A zero-based array of integers, one for each field. Individual field offsets
    can be accessed by using the [] operator.

    *Example: dotnet.field_offsets[0] == 8675309*
