from async_service import Service, TrioManager
import trio
import asyncio

from p2p.service import BaseService


class CustomTrioService(Service):
    async def run(self) -> None:
        print("hello from trio component!")


class CustomAsyncioService(BaseService):

    def __init__(self):
        super().__init__()

    async def _run(self) -> None:
        print("hello from asyncio component!")
        await self.cancellation()


async def test_it():
    trio_service = CustomTrioService()
    asyncio_service = CustomAsyncioService()
    await TrioManager.run_service(trio_service)
    await asyncio_service.run()

if __name__ == '__main__':
    trio.run(test_it)
    # loop = asyncio.get_event_loop()
    # result = loop.run_until_complete(test_it())
