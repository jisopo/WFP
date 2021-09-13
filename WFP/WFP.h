#include <initguid.h>
#include "fwpmu.h"
#include "objbase.h"
#include <stdio.h>
#include <string>
//#include <msclr\marshal.h>
//#include <msclr\marshal_cppstd.h>

// {4EE18DF5-0D5F-4D0D-83FF-5BD8C3746576}
DEFINE_GUID(WFP_CUSTOM_PROVIDER,
    0x4ee18df5, 0xd5f, 0x4d0d, 0x83, 0xff, 0x5b, 0xd8, 0xc3, 0x74, 0x65, 0x76);

// {0E58CF3A-23D1-4726-ADB9-9A456F47040B}
DEFINE_GUID(WFP_CUSTOM_SUBLAYER,
    0xe58cf3a, 0x23d1, 0x4726, 0xad, 0xb9, 0x9a, 0x45, 0x6f, 0x47, 0x4, 0xb);

//using namespace System::Runtime::InteropServices;

//System::Guid FromGUID(_GUID& guid);

//_GUID ToGUID(System::Guid& guid);

extern "C" {

    DWORD initWFP(HANDLE*);

    DWORD closeWFP(HANDLE*);

    //__declspec(dllexport)
    DWORD addRemotePortBlockFilter(UINT16, GUID*);

    //__declspec(dllexport)
    DWORD addRemoteAddressRangeBlockFilter(UINT32, UINT32, GUID*);

    //__declspec(dllexport)
    DWORD removeFilter(GUID);

    DWORD addRemoteAddressBlockFilter(UINT32 Address, GUID* guid);

    BOOL Init();

}