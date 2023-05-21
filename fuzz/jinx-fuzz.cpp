#include <string>
#include "fuzzer/FuzzedDataProvider.h"
#include "../Include/Jinx.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    FuzzedDataProvider fdp(Data, Size);

    auto runtime = Jinx::CreateRuntime();

    const std::string str = fdp.ConsumeBytesAsString(Size);

    runtime->ExecuteScript(str.c_str());

    return 0;
}