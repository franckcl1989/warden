<script setup lang="ts">
import {
  ElButton,
  ElDialog,
  ElForm,
  ElFormItem,
  ElMessage,
  ElMessageBox,
  ElOption,
  ElProgress,
  ElRadio,
  ElRadioGroup,
  ElSelect,
  ElTable,
  ElTableColumn,
  ElTooltip,
} from 'element-plus';
import { onBeforeUnmount, onMounted, ref, watch } from 'vue';
import { useRoute, useRouter } from 'vue-router';

import AsyncState from '@/components/AsyncState.vue';
import ErrorDetail from '@/components/ErrorDetail.vue';
import PaginationBar from '@/components/PaginationBar.vue';
import SensitiveFileLink from '@/components/SensitiveFileLink.vue';
import { ApiError, apiBaseUrl, isApiError, request } from '@/api/client';
import type { FileListResponse, FileUploadContentView, FileView } from '@/api/types';
import { formatBytes, formatDateTime } from '@/lib/format';
import { FILE_STATUS_LABELS, FILE_TYPE_LABELS, label } from '@/lib/labels';
import { registerCacheEntry } from '@/lib/query-cache';
import { useAuthStore } from '@/stores/auth';

// 文件页（PLT-06，PRODUCT_DESIGN §8 / UI_SPEC §9）：
// 上传向导（创建会话 → PUT 流式上传（XHR 进度）→ 完成校验）+
// 元数据列表 + 权限化下载 + 管理员删除（409 处理）。
const auth = useAuthStore();
const route = useRoute();
const router = useRouter();

const fileTypeFilter = ref<string | null>(
  typeof route.query['file_type'] === 'string' ? String(route.query['file_type']) : null,
);
const page = ref(1);
const pageSize = ref(20);

const state = ref<'loading' | 'ready' | 'empty' | 'error' | 'permission_denied'>('loading');
const error = ref<ApiError | null>(null);
const response = ref<FileListResponse | null>(null);

const canManageInputs = (): boolean => auth.permissions.includes('file.manage.input');
const canDownloadOutputs = (): boolean => auth.permissions.includes('file.download.output');
const canDelete = (): boolean => auth.permissions.includes('file.delete');

/** 文件类型 → 下载所需权限（API_CONTRACT §8 / SECURITY §3.1）。 */
function downloadAllowed(file: { file_type: string }): boolean {
  if (file.file_type === 'firmware' || file.file_type === 'virtual_media') {
    return canManageInputs();
  }
  return canDownloadOutputs();
}

async function load(): Promise<void> {
  state.value = 'loading';
  error.value = null;
  try {
    const params = new URLSearchParams({
      page: String(page.value),
      page_size: String(pageSize.value),
    });
    if (fileTypeFilter.value) params.set('file_type', fileTypeFilter.value);
    const result = await request<FileListResponse>(`/files?${params}`);
    response.value = result;
    state.value = result.total === 0 ? 'empty' : 'ready';
  } catch (caught) {
    error.value = caught as ApiError;
    state.value = error.value.code === 'permission_denied' ? 'permission_denied' : 'error';
  }
}

function onTypeChange(): void {
  page.value = 1;
  const query = { ...route.query } as Record<string, string | null>;
  if (fileTypeFilter.value !== null) {
    query['file_type'] = fileTypeFilter.value;
  } else {
    delete query['file_type'];
  }
  void router.replace({ query });
}

watch(
  () => route.query['file_type'],
  (value) => {
    const next = typeof value === 'string' ? value : null;
    if (next !== fileTypeFilter.value) {
      fileTypeFilter.value = next;
    }
    void load();
  },
);

function onPageChange(next: number): void {
  page.value = next;
  void load();
}

function onPageSizeChange(size: number): void {
  pageSize.value = size;
  page.value = 1;
  void load();
}

// ---------- 上传向导 ----------
type UploadPhase = 'form' | 'creating' | 'uploading' | 'completing' | 'done' | 'error';
const wizardOpen = ref(false);
const uploadPhase = ref<UploadPhase>('form');
const uploadType = ref<'firmware' | 'virtual_media'>('firmware');
const selectedFile = ref<File | null>(null);
const uploadProgress = ref(0);
const uploadError = ref<ApiError | null>(null);
const uploadSessionId = ref<string | null>(null);
const uploadResult = ref<FileView | null>(null);

function resetWizard(): void {
  uploadPhase.value = 'form';
  uploadType.value = 'firmware';
  selectedFile.value = null;
  uploadProgress.value = 0;
  uploadError.value = null;
  uploadSessionId.value = null;
  uploadResult.value = null;
}

function openWizard(): void {
  resetWizard();
  wizardOpen.value = true;
}

function onFileChosen(event: Event): void {
  const input = event.target as HTMLInputElement;
  selectedFile.value = input.files?.[0] ?? null;
}

async function createSession(): Promise<void> {
  const file = selectedFile.value;
  if (file === null || !canManageInputs()) {
    return;
  }
  uploadPhase.value = 'creating';
  uploadError.value = null;
  try {
    const created = await request<FileView>('/files/uploads', {
      method: 'POST',
      body: {
        file_type: uploadType.value,
        size_bytes: file.size,
        original_filename: file.name,
      },
    });
    uploadSessionId.value = created.id;
    uploadPhase.value = 'uploading';
    await uploadContent(file);
  } catch (caught) {
    uploadError.value = caught as ApiError;
    uploadPhase.value = 'error';
  }
}

/** PUT 流式上传：XHR 提供上传进度；SHA-256 在 complete 阶段由服务端计算。 */
function uploadContent(file: File): Promise<void> {
  const sessionId = uploadSessionId.value;
  if (sessionId === null) {
    return Promise.reject(new Error('上传会话缺失'));
  }
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open('PUT', `${apiBaseUrl()}/files/uploads/${sessionId}/content`);
    const csrf = auth.csrfToken;
    if (csrf !== null) {
      xhr.setRequestHeader('X-CSRF-Token', csrf);
    }
    xhr.upload.addEventListener('progress', (event) => {
      if (event.lengthComputable) {
        uploadProgress.value = Math.round((event.loaded / event.total) * 100);
      }
    });
    xhr.addEventListener('load', () => {
      if (xhr.status >= 200 && xhr.status < 300) {
        uploadProgress.value = 100;
        try {
          JSON.parse(xhr.responseText) as FileUploadContentView;
        } catch {
          // 忽略回执解析失败：complete 步骤才是权威校验
        }
        uploadPhase.value = 'completing';
        void finishUpload(sessionId, resolve, reject);
        return;
      }
      reject(new ApiError(xhr.status, parseUploadErrorBody(xhr)));
    });
    xhr.addEventListener('error', () => {
      reject(
        new ApiError(0, {
          code: 'internal_error',
          message: '网络连接失败，上传中断',
          details: {},
          request_id: '',
        }),
      );
    });
    xhr.send(file);
  });
}

function parseUploadErrorBody(xhr: XMLHttpRequest): {
  code: ApiError['code'];
  message: string;
  details: Record<string, unknown>;
  request_id: string;
} {
  try {
    const envelope = JSON.parse(xhr.responseText) as {
      error?: {
        code?: string;
        message?: string;
        details?: Record<string, unknown>;
        request_id?: string;
      };
    };
    const code =
      typeof envelope.error?.code === 'string'
        ? (envelope.error.code as ApiError['code'])
        : 'internal_error';
    return {
      code,
      message: envelope.error?.message ?? '上传失败',
      details: envelope.error?.details ?? {},
      request_id: envelope.error?.request_id ?? '',
    };
  } catch {
    return { code: 'internal_error', message: '上传失败', details: {}, request_id: '' };
  }
}

async function finishUpload(
  sessionId: string,
  resolve: () => void,
  reject: (reason: unknown) => void,
): Promise<void> {
  try {
    const finished = await request<FileView>(`/files/uploads/${sessionId}/complete`, {
      method: 'POST',
    });
    uploadResult.value = finished;
    uploadPhase.value = 'done';
    await load();
    resolve();
  } catch (caught) {
    if (isApiError(caught)) {
      uploadError.value = caught as ApiError;
    } else {
      uploadError.value = new ApiError(0, {
        code: 'internal_error',
        message: '文件完成校验失败',
        details: {},
        request_id: '',
      });
    }
    uploadPhase.value = 'error';
    reject(uploadError.value);
  }
}

// ---------- 删除 ----------
// 列表载荷的 links 只含引用关系（FileLinkView：id/device_id/task_id/purpose，
// 无任务运行状态），无法在本地判断"被运行中任务引用"；因此删除按钮不做本地
// 禁用猜测，由服务端 409 device_busy 兜底并在提示后刷新（files_delete 契约）。
async function deleteFile(row: FileView): Promise<void> {
  try {
    await ElMessageBox.confirm(
      `确认删除文件「${row.original_filename}」？删除为逻辑删除，引用历史仍然保留。`,
      '删除文件',
      { type: 'warning', confirmButtonText: '确认删除', cancelButtonText: '取消' },
    );
  } catch {
    return;
  }
  try {
    await request<FileView>(`/files/${row.id}`, { method: 'DELETE' });
    ElMessage.success('文件已删除');
    await load();
  } catch (caught) {
    const apiError = caught as ApiError;
    if (apiError.code === 'device_busy') {
      ElMessage.error('该文件正被运行中的任务引用，无法删除');
      await load();
      return;
    }
    ElMessage.error(`删除失败：${apiError.message}`);
  }
}

function shortSha256(row: { sha256: string | null }): string {
  if (!row.sha256) {
    return '—';
  }
  return `${row.sha256.slice(0, 12)}…`;
}

function emptyText(): string {
  if (fileTypeFilter.value !== null) {
    return '该类型下没有文件';
  }
  return '尚未上传文件';
}

let unregister: (() => void) | null = null;

onMounted(() => {
  void load();
  unregister = registerCacheEntry({ kind: 'files', refetch: () => void load() });
});

onBeforeUnmount(() => {
  unregister?.();
});
</script>

<template>
  <div class="files-page" data-testid="files-page">
    <div class="files-page__toolbar">
      <el-select
        v-model="fileTypeFilter"
        placeholder="文件类型"
        clearable
        class="files-page__filter"
        data-testid="filter-file-type"
        @change="onTypeChange"
      >
        <el-option
          v-for="fileType in [
            'firmware',
            'virtual_media',
            'support_bundle',
            'config_backup',
            'operation_log',
          ]"
          :key="fileType"
          :value="fileType"
          :label="label(FILE_TYPE_LABELS, fileType)"
        />
      </el-select>
      <el-button
        v-if="canManageInputs()"
        type="primary"
        class="files-page__upload"
        data-testid="open-upload"
        @click="openWizard"
      >
        上传文件
      </el-button>
    </div>

    <AsyncState :state="state" :error="error" :empty-text="emptyText()" @retry="load">
      <el-table
        v-if="(response?.items ?? []).length > 0"
        :data="(response?.items ?? []) as FileView[]"
        row-key="id"
        data-testid="files-table"
      >
        <el-table-column label="文件名" min-width="220">
          <template #default="{ row }">
            <SensitiveFileLink
              :file="row as FileView"
              :permitted="downloadAllowed(row as FileView)"
            />
          </template>
        </el-table-column>
        <el-table-column label="类型" width="110">
          <template #default="{ row }">{{ label(FILE_TYPE_LABELS, row.file_type) }}</template>
        </el-table-column>
        <el-table-column label="大小" width="110">
          <template #default="{ row }">{{ formatBytes(row.size_bytes) }}</template>
        </el-table-column>
        <el-table-column label="SHA-256" min-width="150">
          <template #default="{ row }">
            <el-tooltip :content="row.sha256 ?? '—'" placement="top" :disabled="!row.sha256">
              <code>{{ shortSha256(row as FileView) }}</code>
            </el-tooltip>
          </template>
        </el-table-column>
        <el-table-column label="上传者" width="110">
          <template #default="{ row }">{{ row.uploaded_by.username }}</template>
        </el-table-column>
        <el-table-column label="状态" width="90">
          <template #default="{ row }">{{ label(FILE_STATUS_LABELS, row.status) }}</template>
        </el-table-column>
        <el-table-column label="创建时间" width="150">
          <template #default="{ row }">{{ formatDateTime(row.created_at) }}</template>
        </el-table-column>
        <el-table-column label="引用" min-width="180">
          <template #default="{ row }">
            <span v-if="(row.links ?? []).length === 0">—</span>
            <span v-for="link in row.links ?? []" :key="link.id" class="files-page__link-chip">
              {{ link.purpose }}{{ link.device_id ? '·设备' : '' }}{{ link.task_id ? '·任务' : '' }}
            </span>
          </template>
        </el-table-column>
        <el-table-column v-if="canDelete()" label="操作" width="90" fixed="right">
          <template #default="{ row }">
            <el-button
              size="small"
              type="danger"
              plain
              :disabled="row.status === 'uploading'"
              :data-testid="`delete-file-${row.id}`"
              @click="deleteFile(row as FileView)"
            >
              删除
            </el-button>
          </template>
        </el-table-column>
      </el-table>
      <PaginationBar
        v-model:page="page"
        v-model:page-size="pageSize"
        :total="response?.total ?? 0"
        @update:page="onPageChange"
        @update:page-size="onPageSizeChange"
      />
    </AsyncState>

    <!-- 上传向导 -->
    <el-dialog
      v-model="wizardOpen"
      title="上传文件"
      width="560px"
      :close-on-click-modal="false"
      @closed="resetWizard"
    >
      <div class="files-page__wizard" data-testid="upload-wizard">
        <template v-if="uploadPhase === 'form' || uploadPhase === 'creating'">
          <el-form label-width="90px">
            <el-form-item label="用途">
              <el-radio-group v-model="uploadType" data-testid="upload-type">
                <el-radio value="firmware">固件（升级输入）</el-radio>
                <el-radio value="virtual_media">虚拟介质（ISO/USB 镜像）</el-radio>
              </el-radio-group>
            </el-form-item>
            <el-form-item label="文件">
              <input type="file" data-testid="upload-file-input" @change="onFileChosen" />
            </el-form-item>
          </el-form>
          <p v-if="uploadPhase === 'creating'" class="files-page__hint">正在创建上传会话…</p>
          <p class="files-page__hint">
            上传后服务端计算 SHA-256 并执行类型与容量检查；文件就绪前不可被操作表单引用。
          </p>
        </template>

        <template v-if="uploadPhase === 'uploading' || uploadPhase === 'completing'">
          <el-progress :percentage="uploadProgress" data-testid="upload-progress" />
          <p class="files-page__hint" data-testid="upload-phase-text">
            {{
              uploadPhase === 'uploading'
                ? '正在上传内容（服务端按接收字节回执）…'
                : '正在完成校验并计算 SHA-256…'
            }}
          </p>
        </template>

        <template v-if="uploadPhase === 'done'">
          <p class="files-page__success" data-testid="upload-done">
            文件上传完成：{{ uploadResult?.original_filename ?? '' }}（SHA-256 已入库）
          </p>
        </template>

        <template v-if="uploadPhase === 'error'">
          <ErrorDetail v-if="uploadError" :error="uploadError" />
        </template>
      </div>
      <template #footer>
        <el-button
          :disabled="
            uploadPhase === 'uploading' ||
            uploadPhase === 'completing' ||
            uploadPhase === 'creating'
          "
          @click="wizardOpen = false"
        >
          关闭
        </el-button>
        <el-button
          v-if="uploadPhase === 'form' || uploadPhase === 'error'"
          type="primary"
          :disabled="selectedFile === null"
          data-testid="start-upload"
          @click="createSession"
        >
          {{ uploadPhase === 'error' ? '重试上传' : '开始上传' }}
        </el-button>
      </template>
    </el-dialog>
  </div>
</template>

<style scoped>
.files-page__toolbar {
  display: flex;
  gap: 8px;
  margin-bottom: 12px;
}
.files-page__filter {
  width: 200px;
}
.files-page__upload {
  margin-left: auto;
}
.files-page__link-chip {
  display: inline-block;
  margin: 0 6px 4px 0;
  padding: 1px 6px;
  border-radius: 3px;
  background: var(--el-fill-color-light);
  font-size: 12px;
}
.files-page__hint {
  color: var(--warden-status-unknown);
  font-size: 12px;
  margin: 8px 0;
}
.files-page__success {
  color: var(--warden-status-healthy);
}
</style>
