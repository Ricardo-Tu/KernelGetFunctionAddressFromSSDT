# KernelGetFunctionAddressFromSSDT
内核中先加载驱动目录下的ntdll动态链接库，然后通过名称在ntdll中找到函数序号，通过序号到SSDT中找到函数地址。
