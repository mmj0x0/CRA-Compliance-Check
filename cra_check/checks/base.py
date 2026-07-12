from abc import ABC, abstractmethod

from cra_check.report import CheckResult


class Check(ABC):
    id: str
    title: str
    annex_ref: str
    weight: int = 1

    @abstractmethod
    def run(self, ctx) -> CheckResult:
        raise NotImplementedError
