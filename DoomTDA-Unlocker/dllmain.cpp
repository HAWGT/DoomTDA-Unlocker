#include <windows.h>
#include <iostream>
#include <vector>

void* module = GetModuleHandle(nullptr);

BYTE* PatternScan(const char* signature)
{
	static auto pattern_to_byte = [](const char* pattern) {
		auto bytes = std::vector<int>{};
		auto start = const_cast<char*>(pattern);
		auto end = const_cast<char*>(pattern) + strlen(pattern);

		for (auto current = start; current < end; ++current) {
			if (*current == '?') {
				++current;
				if (*current == '?')
					++current;
				bytes.push_back(-1);
			}
			else {
				bytes.push_back(strtoul(current, &current, 16));
			}
		}
		return bytes;
		};

	auto dosHeader = (PIMAGE_DOS_HEADER)module;
	auto ntHeaders = (PIMAGE_NT_HEADERS)((std::uint8_t*)module + dosHeader->e_lfanew);

	auto sizeOfImage = ntHeaders->OptionalHeader.SizeOfImage;
	auto patternBytes = pattern_to_byte(signature);
	auto scanBytes = reinterpret_cast<std::uint8_t*>(module);

	auto s = patternBytes.size();
	auto d = patternBytes.data();

	for (auto i = 0ul; i < sizeOfImage - s; ++i) {
		bool found = true;
		for (auto j = 0ul; j < s; ++j) {
			if (scanBytes[i + j] != d[j] && d[j] != -1) {
				found = false;
				break;
			}
		}
		if (found) {
			return &scanBytes[i];
		}
	}
	return nullptr;
}

void Patch(BYTE* src, BYTE* dst, const ULONG64 size)
{
	DWORD curProtection;
	VirtualProtect(dst, size, PAGE_EXECUTE_READWRITE, &curProtection);
	memcpy_s(dst, size, src, size);
	VirtualProtect(dst, size, curProtection, &curProtection);
}

void Nopify(BYTE* dst, const ULONG64 size)
{
	DWORD curProtection;
	VirtualProtect(dst, size, PAGE_EXECUTE_READWRITE, &curProtection);
	memset(dst, 0x90, size);
	VirtualProtect(dst, size, curProtection, &curProtection);
}

typedef uint64_t(__fastcall* ListOnlineBnetEntitlements_t)(uint64_t a1, uint64_t a2);
inline ListOnlineBnetEntitlements_t Orig_ListOnlineBnetEntitlements;

inline const char JSON[] = R"({"platform":{"code":2000,"message":"success","response":[{"entitlementID":877020,"name":"titan_nvidia_skin"},{"entitlementID":876212,"name":"titan_beryl_skin"},{"entitlementID":877018,"name":"titan_slayers-club_skin"},{"entitlementID":884267,"name":"titan_asus_skin"},{"entitlementID":884631,"name":"titan_faroe_partner-skin"},{"entitlementID":877019,"name":"titan_crm_skin"},{"entitlementID":886688,"name":"titan_mcfarlane-toys_skin"},{"entitlementID":889988,"name":"titan_nova_partner-skin"}]}})";

bool Detour64(BYTE* src, BYTE* dst, const ULONG64 size)
{
	if (size < 12) return false;
	DWORD curProtection;
	VirtualProtect(src, size, PAGE_EXECUTE_READWRITE, &curProtection);
	//mov rax, ULONG64
	*(BYTE*)src = 0x48;
	*(BYTE*)(src + 1) = 0xB8;
	*(ULONG64*)(src + 2) = (ULONG64)dst;
	//jmp rax
	*(BYTE*)(src + 10) = 0xFF;
	*(BYTE*)(src + 11) = 0xE0;
	VirtualProtect(src, size, curProtection, &curProtection);
	return true;
}

BYTE* TrampHook64(BYTE* src, BYTE* dst, const ULONG64 size)
{
	if (size < 12) return 0;
	BYTE* gateway = (BYTE*)VirtualAlloc(0, size + 12, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	memcpy_s(gateway, size, src, size);
	//mov rax, ULONG64
	*(BYTE*)(gateway + size) = 0x48;
	*(BYTE*)(gateway + size + 1) = 0xB8;
	*(ULONG64*)((ULONG64)gateway + size + 2) = (ULONG64)src + size;
	//jmp rax
	*(BYTE*)(gateway + size + 10) = 0xFF;
	*(BYTE*)(gateway + size + 11) = 0xE0;
	Detour64(src, dst, size);
	return gateway;
}

uint64_t __fastcall hk_ListOnlineBnetEntitlements(uint64_t a1, uint64_t a2)
{
	uint64_t v0 = *(uint64_t*)(a1 + 0x8);
	uint64_t v1 = *(uint64_t*)(v0 + 0x8);
	uint64_t v2 = *(uint64_t*)(v1 + 0x130);

	uint64_t origStr = *(uint64_t*)(v2);
	uint64_t origSize = *(uint64_t*)(v2 + 0x8);

	*(int*)(v1 + 0x148) = sizeof(JSON);
	*(int*)(v1 + 0x150) = sizeof(JSON);
	*(uint64_t*)(v2) = (uint64_t)JSON;
	*(int*)(v2 + 0x8) = sizeof(JSON);

	uint64_t retVal = Orig_ListOnlineBnetEntitlements(a1, a2);

	*(int*)(v1 + 0x148) = origSize;
	*(int*)(v1 + 0x150) = origSize;
	*(uint64_t*)(v2) = origStr;
	*(int*)(v2 + 0x8) = origSize;

	return retVal;
}

void Hook()
{
	Orig_ListOnlineBnetEntitlements = reinterpret_cast<ListOnlineBnetEntitlements_t>(PatternScan("40 55 56 57 41 56 48 8D 6C 24 C1 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 45 17"));
	if (!Orig_ListOnlineBnetEntitlements) return;
	Orig_ListOnlineBnetEntitlements = reinterpret_cast<ListOnlineBnetEntitlements_t>(TrampHook64((BYTE*)Orig_ListOnlineBnetEntitlements, (BYTE*)hk_ListOnlineBnetEntitlements, 18));
}

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)Hook, hModule, 0, nullptr);
		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}
