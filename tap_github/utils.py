def camel_to_snake(s):
    return ''.join(['_'+c.lower() if c.isupper() else c for c in s]).lstrip('_')

def camel_to_snake_dict(d):
   if isinstance(d, list):
      return [camel_to_snake_dict(i) if isinstance(i, (dict, list)) else i for i in d]
   return {camel_to_snake(a):camel_to_snake_dict(b) if isinstance(b, (dict, list)) else b for a, b in d.items()}
