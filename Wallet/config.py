import pathlib, json
root_path = pathlib.Path(__file__).parent.resolve()

class transmitData:
    def __init__(self, task: str, param: list):
        self.task = task
        self.param = param

    def toJSON(self):
        return {
            'task': self.task,
            'param': self.param
        }
    
    def encode(self):
        return json.dumps(self.toJSON()).encode()

# print(str(None))

