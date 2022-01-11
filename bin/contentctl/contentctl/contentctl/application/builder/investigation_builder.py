import abc


class InvestigationBuilder(abc.ABC):

    @abc.abstractmethod
    def addInputs(self) -> None:
        pass

    @abc.abstractmethod
    def addLowercaseName(self) -> None:
        pass