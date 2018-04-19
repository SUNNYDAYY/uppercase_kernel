from ipykernel.kernelapp import IPKernelApp
from . import UpperCaseKernel

IPKernelApp.launch_instance(kernel_class=UpperCaseKernel)
