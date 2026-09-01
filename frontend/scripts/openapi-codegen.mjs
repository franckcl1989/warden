// OpenAPI 类型生成流水线：
// 1. 刷新 backend/openapi.gen.json（后端不可用时复用现有导出，离线友好）；
// 2. 用 openapi-typescript 生成 frontend/src/api/generated/openapi.ts。
// 生成产物提交入库；后续里程碑在 CI 校验漂移。
import { execFileSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import openapiTS, { astToString, COMMENT_HEADER } from 'openapi-typescript';

const frontendRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const repoRoot = path.resolve(frontendRoot, '..');
const backendDir = path.join(repoRoot, 'backend');
const openapiPath = path.join(backendDir, 'openapi.gen.json');
const outPath = path.join(frontendRoot, 'src', 'api', 'generated', 'openapi.ts');

function refreshBackendExport() {
    const python =
        process.platform === 'win32'
            ? path.join(backendDir, '.venv', 'Scripts', 'python.exe')
            : path.join(backendDir, '.venv', 'bin', 'python');
    if (!existsSync(python)) {
        return false;
    }
    execFileSync(python, ['-m', 'app.tools.openapi_export'], { cwd: backendDir, stdio: 'inherit' });
    return true;
}

if (!refreshBackendExport()) {
    if (!existsSync(openapiPath)) {
        throw new Error(
            'backend/openapi.gen.json 缺失且后端导出不可用；请先安装后端依赖并运行 app.tools.openapi_export',
        );
    }
    console.warn('后端导出不可用，复用现有 backend/openapi.gen.json');
}

const output = `${COMMENT_HEADER}${astToString(await openapiTS(pathToFileURL(openapiPath)))}`;
await writeFile(outPath, output, 'utf8');
console.log(`OpenAPI 类型已写入 ${path.relative(repoRoot, outPath)}`);
