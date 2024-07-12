import * as os from 'os';
import * as path from 'path';
import * as fs from 'fs';

async function getLinkFilePath()
{
    const packageJsonPath = path.resolve(path.dirname(__filename), '..', 'package.json');

    // TODO: add proper error handling!

    const packageJsonContentString = await fs.promises.readFile(packageJsonPath, 'utf8');

    const packageJsonContent = JSON.parse(packageJsonContentString);

    const version = packageJsonContent.version;

    const linkFileName = `albertziegenhagel-childdebugger-${version}.link`;

    return path.resolve(os.homedir(), '.cppvsdbg', 'extensions', linkFileName);
}

export async function installVsDbgEngineExtensionIntegration(extensionPath : string)
{
    const vsDbgExtensionPath = path.resolve(extensionPath, 'vsdbg-engine-extension', 'bin');

    const linkFilePath = await getLinkFilePath();

    await fs.promises.mkdir(path.dirname(linkFilePath), {recursive: true});

    // TODO: Instead of always overwriting the file, we might want to check whether it exists first?
    //       And if it exists, should we check that it's contents is correct? What if it is not?
    //       Do we want to overwrite it or keep the current contents? Should we at least emit a warning?
    await fs.promises.writeFile(linkFilePath, vsDbgExtensionPath, { encoding: 'utf8', flag: 'w' });
}

export function uninstallVsDbgEngineExtensionIntegration()
{
    // Simply ignore the errors. We can't do anything about them anyways?
    getLinkFilePath().then((linkFilePath) => {
        fs.unlink(linkFilePath, (err) => {});
    });
}
