# 违规生成器（fixture）：把公共实现复制回来，且未 import
def port_free(port):
    return False


def main():
    return port_free(1)
