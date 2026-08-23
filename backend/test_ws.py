import asyncio
import websockets

async def main():
    print("Connecting...")

    try:
        async with websockets.connect("ws://localhost:8000/ws/events") as ws:
            print("CONNECTED!")

            while True:
                message = await ws.recv()
                print("EVENT:", message)

    except Exception as e:
        print("WEBSOCKET ERROR:", repr(e))

asyncio.run(main())