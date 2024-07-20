import * as os from 'os';
import * as path from 'path';
import * as fs from 'fs';

function getLinkFilePath()
{
    const publisher     = "albertziegenhagel";
    const extensionName = "childdebugger";

    const linkFileName = `${publisher}-${extensionName}.link`;

    return path.resolve(os.homedir(), '.cppvsdbg', 'extensions', linkFileName);
}

export async function installVsDbgEngineExtensionIntegration(extensionPath : string)
{
    const vsDbgExtensionPath = path.resolve(extensionPath, 'vsdbg-engine-extension', 'bin');

    const linkFilePath = getLinkFilePath();

    await fs.promises.mkdir(path.dirname(linkFilePath), {recursive: true});

    // TODO: Instead of always overwriting the file, we might want to check whether it exists first?
    //       And if it exists, should we check that it's contents is correct? What if it is not?
    //       Do we want to overwrite it or keep the current contents? Should we at least emit a warning?
    await fs.promises.writeFile(linkFilePath, vsDbgExtensionPath, { encoding: 'utf8', flag: 'w' });
}

export function uninstallVsDbgEngineExtensionIntegration()
{
    const linkFilePath = getLinkFilePath();

    // Simply ignore the error. We can't do anything about it anyways?
    fs.unlink(linkFilePath, (err) => {});
}
