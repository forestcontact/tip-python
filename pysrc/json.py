import json as json_

def Marshal(obj):
    obj = dict(sorted(obj.items(), key=lambda x: x[0]))
    return json_.dumps(obj, separators=(',', ':'))

def Unmarshal(obj):
    obj = json_.loads(obj)
    obj = dict(sorted(obj.items(), key=lambda x: x[0]))
    return obj

def loads(s):
    return json_.loads(s)
