#include "stdafx.h"
#include "objbase.h"
#include <stdio.h>
#include "WFP.h"
#include <Windows.h>


GUID PROVIDER_KEY =
{
    0x5fb216a8,
    0xe2e8,
    0x4024,
    { 0xb8, 0x53, 0x39, 0x1a, 0x41, 0x68, 0x64, 0x1e }
};

System::Guid FromGUID(_GUID& guid) {
    return System::Guid(guid.Data1, guid.Data2, guid.Data3,
        guid.Data4[0], guid.Data4[1],
        guid.Data4[2], guid.Data4[3],
        guid.Data4[4], guid.Data4[5],
        guid.Data4[6], guid.Data4[7]);
}

_GUID ToGUID(System::Guid& guid) {
    array<System::Byte>^ guidData = guid.ToByteArray();
    pin_ptr<System::Byte> data = &(guidData[0]);
    return *(_GUID*)data;
}

DWORD initWFP()
{
    // Open engine
    FWPM_SESSION0   Session;

    RtlZeroMemory(&Session, sizeof(Session));

    Session.displayData.name = L"WFPCustomSession";
    Session.displayData.description = L"WFP Custom Session";

    DWORD Status = FwpmEngineOpen0(
        NULL,
        RPC_C_AUTHN_DEFAULT,
        NULL,
        &Session,
        &hEngine
        );

    if (ERROR_SUCCESS != Status)
    {
        printf("FwpmEngineOpen0 failed with status 0x%.8lx.\n", Status);
        return Status;
    }

    // Register provider
    FWPM_PROVIDER0 Provider;

    RtlZeroMemory(&Provider, sizeof(Provider));

    Provider.providerKey = WFP_CUSTOM_PROVIDER;
    Provider.displayData.name = L"WFPCustomProvider";
    Provider.displayData.description = L"WFP Custom Provider";

    Status = FwpmProviderAdd0(hEngine, &Provider, NULL);

    if (ERROR_SUCCESS != Status && FWP_E_ALREADY_EXISTS != Status)
    {
        printf("FwpmProviderAdd0 failed with status 0x%.8lx.\n", Status);
        return Status;
    }

    // Register sublayer
    FWPM_SUBLAYER0 Sublayer;
    RtlZeroMemory(&Sublayer, sizeof(Sublayer));

    Sublayer.subLayerKey = WFP_CUSTOM_SUBLAYER;
    Sublayer.displayData.name = L"WFPCustomSublayer";
    Sublayer.displayData.description = L"WFP Custom Sublayer";
    Sublayer.providerKey = (GUID *)&WFP_CUSTOM_PROVIDER;
    Sublayer.weight = 0x123;

    Status = FwpmSubLayerAdd0(hEngine, &Sublayer, NULL);

    if (ERROR_SUCCESS != Status && FWP_E_ALREADY_EXISTS != Status)
    {
        printf("FwpmSublayerAdd0 failed with status 0x%.8lx.\n", Status);
        return Status;
    }

    return ERROR_SUCCESS;
}

// удаляем созданный слой и удаляем провайдера перед закрытием hEngine
DWORD unregister()
{
    DWORD status = FwpmSubLayerDeleteByKey0(hEngine, &WFP_CUSTOM_SUBLAYER);
    if (ERROR_SUCCESS != status)
    {
        printf("unregister FwpmSubLayerDeleteByKey0 failed with status 0x%.8lx.\n", status);
        return status;
    }

    status = FwpmProviderDeleteByKey(hEngine, &WFP_CUSTOM_PROVIDER);
    if (ERROR_SUCCESS != status)
    {
        printf("unregister FwpmProviderDeleteByKey failed with status 0x%.8lx.\n", status);
        return status;
    }

    return status;
}

DWORD closeWFP()
{
    DWORD status = FwpmEngineClose0(hEngine);

    if (ERROR_SUCCESS != status)
    {
        printf("closeWFP failed with status 0x%.8lx.\n", status);
        return status;
    }

    return ERROR_SUCCESS;
}

int ipStringToNumber(const char*       pDottedQuad,
    unsigned int *    pIpAddr)
{
    unsigned int            byte3;
    unsigned int            byte2;
    unsigned int            byte1;
    unsigned int            byte0;
    char              dummyString[2];

    /* The dummy string with specifier %1s searches for a non-whitespace char
    * after the last number. If it is found, the result of sscanf will be 5
    * instead of 4, indicating an erroneous format of the ip-address.
    */
    if (sscanf(pDottedQuad, "%u.%u.%u.%u%1s",
        &byte3, &byte2, &byte1, &byte0, dummyString) == 4)
    {
        if ((byte3 < 256)
            && (byte2 < 256)
            && (byte1 < 256)
            && (byte0 < 256)
            )
        {
            *pIpAddr = (byte3 << 24)
                + (byte2 << 16)
                + (byte1 << 8)
                + byte0;

            return 1;
        }
    }
    return 0;
}

//__declspec(dllexport)
DWORD addRemoteAddressRangeBlockFilter(UINT32 loAddress, UINT32 hiAddress, GUID* guid)
{
    DWORD Status;

    // Register filter
    GUID  filter_guid;
    CoCreateGuid(&filter_guid);
    memcpy(guid, &filter_guid, sizeof(filter_guid));
    FWPM_FILTER_CONDITION0 Conds[1];

    FWP_RANGE0 addressRange;
    addressRange.valueLow.type = FWP_UINT32;
    addressRange.valueLow.uint32 = loAddress;
    addressRange.valueHigh.type = FWP_UINT32;
    addressRange.valueHigh.uint32 = hiAddress;

    Conds[0].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
    Conds[0].matchType = FWP_MATCH_RANGE;
    Conds[0].conditionValue.type = FWP_RANGE_TYPE;
    Conds[0].conditionValue.rangeValue = &addressRange;

    FWPM_FILTER0 Filter;
    RtlZeroMemory(&Filter, sizeof(Filter));

    Filter.providerKey = NULL;
    Filter.displayData.name = L"WFPCustomRemoteAddressRangeFilter";
    Filter.displayData.description = L"WFP Custom Remote Address Range Filter";
    Filter.layerKey = FWPM_LAYER_INBOUND_IPPACKET_V4;
    Filter.subLayerKey = WFP_CUSTOM_SUBLAYER;
    Filter.weight.type = FWP_UINT8;
    Filter.numFilterConditions = 1;
    Filter.filterCondition = &Conds[0];
    Filter.action.type = FWP_ACTION_BLOCK;

    Filter.filterKey = filter_guid;
    Filter.weight.uint8 = 1;

    Status = FwpmFilterAdd0(hEngine, &Filter, NULL, NULL);

    if (ERROR_SUCCESS != Status)
    {
        printf("FwpmFilterAdd0 failed with status 0x%.8lx.\n", Status);
        return Status;
    }

    return ERROR_SUCCESS;
}

DWORD addRemoteAddressBlockFilter(UINT32 Address, GUID* guid_inbound, GUID* guid_outbound)
{
    // Register filter
    GUID  filter_inbound;
    CoCreateGuid(&filter_inbound);
    memcpy(guid_inbound, &filter_inbound, sizeof(filter_inbound));

    GUID  filter_outbound;
    CoCreateGuid(&filter_outbound);
    memcpy(guid_outbound, &filter_outbound, sizeof(filter_outbound));


    FWPM_FILTER_CONDITION0 Conds_outbound[1];
    FWPM_FILTER_CONDITION0 Conds_inbound[1];
    int conditionsCount = 0;

    Conds_outbound[conditionsCount].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
    Conds_outbound[conditionsCount].matchType = FWP_MATCH_EQUAL;
    Conds_outbound[conditionsCount].conditionValue.type = FWP_UINT32;
    Conds_outbound[conditionsCount].conditionValue.uint32 = Address;

    Conds_inbound[conditionsCount].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
    Conds_inbound[conditionsCount].matchType = FWP_MATCH_EQUAL;
    Conds_inbound[conditionsCount].conditionValue.type = FWP_UINT32;
    Conds_inbound[conditionsCount].conditionValue.uint32 = Address;
    conditionsCount++;

    FWPM_FILTER0 FilterOutbound;
    RtlZeroMemory(&FilterOutbound, sizeof(FilterOutbound));

    FilterOutbound.providerKey = NULL;
    FilterOutbound.displayData.name = L"WFPCustomRemoteAddressRangeFilter";
    FilterOutbound.displayData.description = L"WFP Custom Remote Address Range Filter";
    FilterOutbound.layerKey = FWPM_LAYER_OUTBOUND_IPPACKET_V4;
    FilterOutbound.subLayerKey = WFP_CUSTOM_SUBLAYER;
    FilterOutbound.weight.type = FWP_UINT8;
    FilterOutbound.numFilterConditions = 1;
    FilterOutbound.filterCondition = &Conds_outbound[0];
    FilterOutbound.action.type = FWP_ACTION_BLOCK;

    FilterOutbound.filterKey = filter_outbound;
    FilterOutbound.weight.uint8 = 1;

    DWORD Status = FwpmFilterAdd0(hEngine, &FilterOutbound, NULL, NULL/*&FilterId*/);

    if (ERROR_SUCCESS != Status)
    {
        printf("FwpmFilterAdd0 failed with status 0x%.8lx.\n", Status);
        return Status;
    }

    FWPM_FILTER0 FilterInbound;
    RtlZeroMemory(&FilterInbound, sizeof(FilterInbound));

    FilterInbound.providerKey = NULL;
    FilterInbound.displayData.name = L"WFPCustomRemoteAddressRangeFilter";
    FilterInbound.displayData.description = L"WFP Custom Remote Address Range Filter";
    FilterInbound.layerKey = FWPM_LAYER_INBOUND_IPPACKET_V4;
    FilterInbound.subLayerKey = WFP_CUSTOM_SUBLAYER;
    FilterInbound.weight.type = FWP_UINT8;
    FilterInbound.numFilterConditions = 1;
    FilterInbound.filterCondition = &Conds_inbound[0];
    FilterInbound.action.type = FWP_ACTION_BLOCK;

    FilterInbound.filterKey = filter_inbound;
    FilterInbound.weight.uint8 = 1;

    Status = FwpmFilterAdd0(hEngine, &FilterInbound, NULL, NULL);

    if (ERROR_SUCCESS != Status)
    {
        printf("FwpmFilterAdd0 failed with status 0x%.8lx.\n", Status);
        return Status;
    }

    return ERROR_SUCCESS;
}

//__declspec(dllexport)
DWORD removeFilter(GUID guid)
{
    DWORD Status = ERROR_SUCCESS;

    if (ERROR_SUCCESS != Status)
    {
        printf("initWFP failed with status 0x%.8lx.\n", Status);
        return Status;
    }

    Status = FwpmFilterDeleteByKey0(hEngine, &guid);

    if (ERROR_SUCCESS != Status)
    {
        printf("FwpmFilterDeleteByKey0 failed with status 0x%.8lx.\n", Status);
        return Status;
    }

    return ERROR_SUCCESS;
}
