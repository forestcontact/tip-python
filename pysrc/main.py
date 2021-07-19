import os
import sys

import toml
import uvicorn
from .server import app
from .app import parse_args

if __name__ == '__main__':
    current_dir = os.path.dirname(__file__)
    args = parse_args(sys.argv[1:])
    if args.sub in ('api'):
        config = toml.load(args.config)
        print(config['api']['port'])
        uvicorn.run('tip.main:app', host='0.0.0.0', port=config['api']['port'], reload=True, access_log=False, reload_dirs=[current_dir])
        # uvicorn.run('tip.main:app', host='0.0.0.0', port=7008, reload=True, access_log=False, reload_dirs=[current_dir])
    else:
        args.func(args)
