print("hello, world!")
coroutine.yield()  -- this will cause the process to save state and exit
print("goodbye, world...")
