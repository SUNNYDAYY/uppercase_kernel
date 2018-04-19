import unittest
import jupyter_kernel_test

class MyKernelTests(jupyter_kernel_test.KernelTests):

    kernel_name = "uppercase"
    language_name = "Any text"
    code_execute_result = [
        {'code': 'abc', 'result': 'ABC'}
    ]

if __name__ == '__main__':
    unittest.main()
