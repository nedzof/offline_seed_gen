import random
from typing import List, Tuple, Union, Optional

class ndarray:
    def __init__(self, data: List[Union[int, float]]):
        self.data = data

    def tolist(self) -> List[Union[int, float]]:
        return self.data

    def __len__(self) -> int:
        return len(self.data)

    def __getitem__(self, index: int) -> Union[int, float]:
        return self.data[index]

def array(data: List[Union[int, float]]) -> ndarray:
    return ndarray(data)

def random_bytes(size: int) -> bytes:
    return bytes(random.randint(0, 255) for _ in range(size))

def frombuffer(buffer: bytes, dtype: str = 'uint8') -> ndarray:
    return ndarray(list(buffer))

def zeros(shape: Union[int, Tuple[int, ...]], dtype: str = 'float64') -> ndarray:
    if isinstance(shape, int):
        return ndarray([0] * shape)
    return ndarray([[0] * shape[1] for _ in range(shape[0])])

def ones(shape: Union[int, Tuple[int, ...]], dtype: str = 'float64') -> ndarray:
    if isinstance(shape, int):
        return ndarray([1] * shape)
    return ndarray([[1] * shape[1] for _ in range(shape[0])])

def arange(start: int, stop: Optional[int] = None, step: int = 1) -> ndarray:
    if stop is None:
        stop = start
        start = 0
    return ndarray(list(range(start, stop, step)))

def linspace(start: float, stop: float, num: int) -> ndarray:
    step = (stop - start) / (num - 1)
    return ndarray([start + i * step for i in range(num)])

def histogram(a: ndarray, bins: int) -> Tuple[ndarray, ndarray]:
    min_val = min(a.data)
    max_val = max(a.data)
    bin_width = (max_val - min_val) / bins
    
    hist = [0] * bins
    for val in a.data:
        bin_index = min(int((val - min_val) / bin_width), bins - 1)
        hist[bin_index] += 1
    
    bin_edges = [min_val + i * bin_width for i in range(bins + 1)]
    return ndarray(hist), ndarray(bin_edges) 