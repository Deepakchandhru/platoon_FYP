#!/usr/bin/env python3
import asyncio
import grpc
import platoon_pb2
import platoon_pb2_grpc

async def watch_all():
    async with grpc.aio.insecure_channel('localhost:50051') as ch:
        stub = platoon_pb2_grpc.PlatoonServiceStub(ch)
        print("Watching events... (Ctrl+C to stop)")
        try:
            request = platoon_pb2.WatchRequest(pids=[]) 
            async for evt in stub.WatchPlatoons(request):
                print(f"[Event] {evt.message} | Platoon: {evt.pid} | Actor: {evt.actor_id}")
        except grpc.aio.AioRpcError as e:
            print("RPC Error:", e)

if __name__ == "__main__":
    try:
        asyncio.run(watch_all())
    except KeyboardInterrupt:
        print("\nStopped watching events.")