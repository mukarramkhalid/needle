# Needle
A multiprocessing blind SQL injection script to handle cases where sqlmap fails.

It's still a work in progress.

The `infer` method expects you to specify what's `True` and `False`. You need to set that accordingly.

A few examples are given below.

### Example 1
```python
def infer(self, response):
    '''
    If response length is less than 50, it's False
    Otherwise, it's True.
    '''
    if len(response.content) < 50:
        return False
    return True
```

### Example 2
```python
def infer(self, response):
    '''
    If response status code is 200, it's True
    Otherwise, it's False
    '''
    if response.status_code == 200:
        return True
    return False
```
