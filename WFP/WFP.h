#include <initguid.h>
#include "fwpmu.h"
#include "objbase.h"
#include <stdio.h>
#include <string>
#include <msclr\marshal.h>
#include <msclr\marshal_windows.h>
#include <msclr\marshal_cppstd.h>

// {4EE18DF5-0D5F-4D0D-83FF-5BD8C3746576}
DEFINE_GUID(WFP_CUSTOM_PROVIDER,
    0x4ee18df5, 0xd5f, 0x4d0d, 0x83, 0xff, 0x5b, 0xd8, 0xc3, 0x74, 0x65, 0x76);

// {0E58CF3A-23D1-4726-ADB9-9A456F47040B}
DEFINE_GUID(WFP_CUSTOM_SUBLAYER,
    0xe58cf3a, 0x23d1, 0x4726, 0xad, 0xb9, 0x9a, 0x45, 0x6f, 0x47, 0x4, 0xb);

#define IPPROTO_UDP 6

System::Guid FromGUID(_GUID& guid);

_GUID ToGUID(System::Guid& guid);

int ipStringToNumber(const char*       pDottedQuad,
                     unsigned int *    pIpAddr);

static HANDLE hEngine;

extern "C" {

    DWORD initWFP();

    DWORD closeWFP();

    DWORD unregister();

    //__declspec(dllexport)
    DWORD addRemoteAddressRangeBlockFilter(UINT32, UINT32, GUID*);

    //__declspec(dllexport)
    DWORD removeFilter(GUID);

    DWORD addRemoteAddressBlockFilter(UINT32 Address, GUID* guid, GUID* guid2);

    DWORD addRemoteAddressRangeBlockFilter(UINT32 loAddress, UINT32 hiAddress, GUID* guid);

    BOOL Init();

    public ref class jisopoWFP
    {
    public:
        static DWORD WFPInit()
        {
            DWORD result = initWFP();
            return result;
        };

        static DWORD banIpRange(System::String^ loIp, System::String^ hiIp, System::Guid% guid)
        {
            unsigned int targetIpUintlo;
            unsigned int targetIpUinthi;
            std::string targetIpUintloStr = msclr::interop::marshal_as<std::string, System::String^>(loIp);
            std::string targetIpUinthiStr = msclr::interop::marshal_as<std::string, System::String^>(hiIp);
            DWORD result = ipStringToNumber(targetIpUintloStr.c_str(), &targetIpUintlo);
            if (!result)
            {
                return result;
            }
            result = ipStringToNumber(targetIpUinthiStr.c_str(), &targetIpUinthi);
            if (!result)
            {
                return result;
            }

            GUID ruleGuid;
            result = addRemoteAddressRangeBlockFilter(targetIpUintlo, targetIpUinthi, &ruleGuid);
            guid = FromGUID(ruleGuid);
            return result;
        }

        static DWORD banIp(System::String^ targetIp, System::Guid% guid, System::Guid% guid2)
        {
            unsigned int targetIpUint;
            std::string targetIpStr = msclr::interop::marshal_as<std::string, System::String^>(targetIp);
            DWORD result = ipStringToNumber(targetIpStr.c_str(), &targetIpUint);
            if (!result)
            {
                return result;
            }
            GUID ruleGuid;
            GUID ruleGuid2;
            result = addRemoteAddressBlockFilter((UINT32)targetIpUint, &ruleGuid, &ruleGuid2);
            guid = FromGUID(ruleGuid);
            guid2 = FromGUID(ruleGuid2);
            return result;
        }

        static DWORD removeRule(System::Guid ruleGuid)
        {
            GUID guid = ToGUID(ruleGuid);
            return removeFilter(guid);
        }

        static DWORD WFPClose()
        {
            unregister();
            return closeWFP();
        }
    };
}