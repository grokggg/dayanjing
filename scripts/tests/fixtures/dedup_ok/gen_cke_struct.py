# 合规生成器（fixture）：不持有本地副本，走公共模块
import tls_truth


def main():
    return tls_truth.probe_openssl(1)
