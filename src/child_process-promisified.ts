import cp = require('child_process');
import util = require('util');
export const exec: (cmd: string, opts?: any) => Promise<any> = util.promisify(cp.exec);