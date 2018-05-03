from ipykernel.kernelbase import Kernel

class UpperCaseKernel(Kernel):
    implementation = 'UpperCase'
    implementation_version = '1.0'
    language = 'uppercase'
    language_version = [0,0,1]
    language_info = {
        'name': 'uppercase',
        'mimetype': 'text/plain',
        'file_extension': '.txt',
        'version':'1'
    }
    banner = "UpperCaseKernel"

    def do_execute(self, code, silent, store_history=True, user_expressions=None,
                   allow_stdin=False):
        if not silent:
            code = code.upper()
            stream_content = {'name': 'stdout', 'text': code}
            self.send_response(self.iopub_socket, 'stream', stream_content)

        return {'status': 'ok',
                # The base class increments the execution count
                'execution_count': self.execution_count,
                'payload': [],
                'user_expressions': {},
               }
