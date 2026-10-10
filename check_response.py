import json

with open('/Users/yamijala/.gemini/antigravity/brain/ec84c16d-f5b9-4dea-b222-b8b184b3ef14/.system_generated/tasks/task-7590.log', 'r') as f:
    text = f.read()
    # just grep for the error or print the whole thing
    print("LOG:")
    print(text[-2000:])
