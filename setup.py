from distutils.core import setup



setup(
    name='uppercase_kernel',
    version='1.0',
    packages=['uppercase_kernel'],
    description='Simple example kernel for Jupyter',
    install_requires=[
        'jupyter_client', 'IPython', 'ipykernel'
    ],
    classifiers=[
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Programming Language :: Python :: 3',
    ],
)
