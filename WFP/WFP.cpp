#include "stdafx.h"
#include "fwpmu.h"
#include "objbase.h"
#include <stdio.h>
#include "WFP.h"
#include <Windows.h>
#include <Psapi.h>
#include <tlhelp32.h>


GUID PROVIDER_KEY =
{
	0x5fb216a8,
	0xe2e8,
	0x4024,
	{ 0xb8, 0x53, 0x39, 0x1a, 0x41, 0x68, 0x64, 0x1e }
};

	DWORD initWFP(HANDLE* hEngine)
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
			hEngine
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

		Status = FwpmProviderAdd0(*hEngine, &Provider, NULL);

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

		Status = FwpmSubLayerAdd0(*hEngine, &Sublayer, NULL);

		if (ERROR_SUCCESS != Status && FWP_E_ALREADY_EXISTS != Status)
		{
			printf("FwpmSublayerAdd0 failed with status 0x%.8lx.\n", Status);
			return Status;
		}

		return ERROR_SUCCESS;
	}

	//__declspec(dllexport)
		DWORD addRemotePortBlockFilter(UINT16 target, GUID* guid)
	{
		HANDLE hEngine;

		DWORD Status = initWFP(&hEngine);

		if (ERROR_SUCCESS != Status)
		{
			printf("initWFP failed with status 0x%.8lx.\n", Status);
			return Status;
		}

		// Register filter
		GUID  filter_guid;
		CoCreateGuid(&filter_guid);
		memcpy(guid, &filter_guid, sizeof(filter_guid));
		FWPM_FILTER_CONDITION0 Conds[1];

		Conds[0].fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
		Conds[0].matchType = FWP_MATCH_EQUAL;
		Conds[0].conditionValue.type = FWP_UINT16;
		Conds[0].conditionValue.uint16 = target;

		FWPM_FILTER0 Filter;
		RtlZeroMemory(&Filter, sizeof(Filter));

		Filter.providerKey = NULL;
		Filter.displayData.name = L"WFPCustomRemotePortFilter";
		Filter.displayData.description = L"WFP Custom Remote Port Filter";
		Filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
		Filter.subLayerKey = WFP_CUSTOM_SUBLAYER;
		Filter.weight.type = FWP_UINT8;
		Filter.numFilterConditions = 1;
		Filter.filterCondition = &Conds[0];
		Filter.action.type = FWP_ACTION_BLOCK;

		UINT64 FilterId;

		Filter.filterKey = filter_guid;
		Filter.weight.uint8 = 1;

		Status = FwpmFilterAdd0(hEngine, &Filter, NULL, &FilterId);

		if (ERROR_SUCCESS != Status)
		{
			printf("FwpmFilterAdd0 failed with status 0x%.8lx.\n", Status);
			return Status;
		}

		Status = FwpmEngineClose0(hEngine);

		if (ERROR_SUCCESS != Status)
		{
			printf("closeWFP failed with status 0x%.8lx.\n", Status);
			return Status;
		}

		return ERROR_SUCCESS;
	}

	//__declspec(dllexport)
		DWORD addRemoteAddressRangeBlockFilter(UINT32 loAddress, UINT32 hiAddress, GUID* guid)
	{
		HANDLE hEngine;

		DWORD Status = initWFP(&hEngine);

		if (ERROR_SUCCESS != Status)
		{
			printf("initWFP failed with status 0x%.8lx.\n", Status);
			return Status;
		}

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
		Filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
		Filter.subLayerKey = WFP_CUSTOM_SUBLAYER;
		Filter.weight.type = FWP_UINT8;
		Filter.numFilterConditions = 1;
		Filter.filterCondition = &Conds[0];
		Filter.action.type = FWP_ACTION_BLOCK;

		UINT64 FilterId;

		Filter.filterKey = filter_guid;
		Filter.weight.uint8 = 1;

		Status = FwpmFilterAdd0(hEngine, &Filter, NULL, &FilterId);

		if (ERROR_SUCCESS != Status)
		{
			printf("FwpmFilterAdd0 failed with status 0x%.8lx.\n", Status);
			return Status;
		}

		Status = FwpmEngineClose0(hEngine);

		if (ERROR_SUCCESS != Status)
		{
			printf("closeWFP failed with status 0x%.8lx.\n", Status);
			return Status;
		}

		return ERROR_SUCCESS;
	}

        DWORD addRemoteAddressBlockFilter(UINT32 Address, GUID* guid)
        {
            HANDLE hEngine;

            DWORD Status = initWFP(&hEngine);

            if (ERROR_SUCCESS != Status)
            {
                printf("initWFP failed with status 0x%.8lx.\n", Status);
                return Status;
            }

            // Register filter
            GUID  filter_guid;
            CoCreateGuid(&filter_guid);
            memcpy(guid, &filter_guid, sizeof(filter_guid));
            FWPM_FILTER_CONDITION0 Conds[1];

            Conds[0].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
            Conds[0].matchType = FWP_MATCH_EQUAL;
            Conds[0].conditionValue.type = FWP_UINT32;
            Conds[0].conditionValue.uint32 = Address;

            FWPM_FILTER0 Filter;
            RtlZeroMemory(&Filter, sizeof(Filter));

            Filter.providerKey = NULL;
            Filter.displayData.name = L"WFPCustomRemoteAddressRangeFilter";
            Filter.displayData.description = L"WFP Custom Remote Address Range Filter";
            Filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
            Filter.subLayerKey = WFP_CUSTOM_SUBLAYER;
            Filter.weight.type = FWP_UINT8;
            Filter.numFilterConditions = 1;
            Filter.filterCondition = &Conds[0];
            Filter.action.type = FWP_ACTION_BLOCK;

            UINT64 FilterId;

            Filter.filterKey = filter_guid;
            Filter.weight.uint8 = 1;

            Status = FwpmFilterAdd0(hEngine, &Filter, NULL, &FilterId);

            if (ERROR_SUCCESS != Status)
            {
                printf("FwpmFilterAdd0 failed with status 0x%.8lx.\n", Status);
                return Status;
            }

            Status = FwpmEngineClose0(hEngine);

            if (ERROR_SUCCESS != Status)
            {
                printf("closeWFP failed with status 0x%.8lx.\n", Status);
                return Status;
            }

            return ERROR_SUCCESS;
        }

	//__declspec(dllexport)
		DWORD removeFilter(GUID guid)
	{
		HANDLE hEngine;

		DWORD Status = initWFP(&hEngine);

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

		Status = FwpmEngineClose0(hEngine);

		if (ERROR_SUCCESS != Status)
		{
			printf("closeWFP failed with status 0x%.8lx.\n", Status);
			return Status;
		}

		return ERROR_SUCCESS;
	}