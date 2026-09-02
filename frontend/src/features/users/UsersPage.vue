<script setup lang="ts">
import {
  ElButton,
  ElDialog,
  ElForm,
  ElFormItem,
  ElInput,
  ElMessage,
  ElMessageBox,
  ElOption,
  ElSelect,
  ElTable,
  ElTableColumn,
} from 'element-plus';
import { computed, onMounted, reactive, ref } from 'vue';

import AsyncState from '@/components/AsyncState.vue';
import ErrorDetail from '@/components/ErrorDetail.vue';
import PaginationBar from '@/components/PaginationBar.vue';
import type { ApiError } from '@/api/client';
import type { UserListResponse, UserView } from '@/api/types';
import { request } from '@/api/client';
import { ROLE_LABELS, USER_STATUS_LABELS, label } from '@/lib/labels';
import { formatDateTime } from '@/lib/format';
import { useAuthStore } from '@/stores/auth';

// 用户与角色页（PLT-01，仅管理员；UI_SPEC §2 管理员专属菜单）。
const auth = useAuthStore();

const state = ref<'loading' | 'ready' | 'error' | 'permission_denied'>('loading');
const error = ref<ApiError | null>(null);
const list = ref<UserListResponse | null>(null);
const page = ref(1);
const pageSize = ref(20);
const sort = ref('username');
const sortOrder = ref<'ascending' | 'descending' | null>(null);

const roles = ['admin', 'operator', 'viewer'];

async function load(): Promise<void> {
  if (!auth.isAdmin) {
    state.value = 'permission_denied';
    return;
  }
  state.value = 'loading';
  error.value = null;
  try {
    list.value = await loadPage();
    state.value = 'ready';
  } catch (caught) {
    error.value = caught as ApiError;
    if (error.value.code === 'permission_denied') {
      state.value = 'permission_denied';
    } else {
      state.value = 'error';
    }
  }
}

async function loadPage(): Promise<UserListResponse> {
  const params = new URLSearchParams({
    page: String(page.value),
    page_size: String(pageSize.value),
  });
  if (sortOrder.value === 'ascending') params.set('sort', sort.value);
  if (sortOrder.value === 'descending') params.set('sort', `-${sort.value}`);
  return request<UserListResponse>(`/users?${params.toString()}`);
}

function onSortChange({
  prop,
  order,
}: {
  prop: string | null;
  order: 'ascending' | 'descending' | null;
}): void {
  if (prop === null) return;
  sort.value = prop;
  sortOrder.value = order;
  page.value = 1;
  void load();
}

function onPageChange(next: number): void {
  page.value = next;
  void load();
}

function onPageSizeChange(size: number): void {
  pageSize.value = size;
  page.value = 1;
  void load();
}

interface CreateForm {
  username: string;
  displayName: string;
  role: string;
  password: string;
  confirmPassword: string;
}

const createVisible = ref(false);
const createForm = reactive<CreateForm>({
  username: '',
  displayName: '',
  role: 'viewer',
  password: '',
  confirmPassword: '',
});
const creating = ref(false);
const createError = ref<ApiError | null>(null);

function createPolicyViolation(): string | null {
  if (!createForm.username) return '请输入用户名';
  if (!createForm.displayName) return '请输入显示名称';
  if (createForm.password.length < 12) return '密码长度至少 12 位';
  if (createForm.password.toLowerCase().includes(createForm.username.toLowerCase())) {
    return '密码不能包含用户名';
  }
  if (createForm.password !== createForm.confirmPassword) return '两次输入的密码不一致';
  return null;
}

async function createUser(): Promise<void> {
  const violation = createPolicyViolation();
  if (violation) {
    ElMessage.warning(violation);
    return;
  }
  creating.value = true;
  createError.value = null;
  try {
    await request('/users', {
      method: 'POST',
      body: {
        username: createForm.username,
        display_name: createForm.displayName,
        role: createForm.role,
        password: createForm.password,
      },
    });
    ElMessage.success('用户已创建');
    createVisible.value = false;
    createForm.username = '';
    createForm.displayName = '';
    createForm.role = 'viewer';
    createForm.password = '';
    createForm.confirmPassword = '';
    await load();
  } catch (caught) {
    createError.value = caught as ApiError;
  } finally {
    creating.value = false;
  }
}

interface EditForm {
  displayName: string;
  role: string;
  version: number;
}

const editVisible = ref(false);
const editTarget = ref<UserView | null>(null);
const editForm = reactive<EditForm>({ displayName: '', role: 'viewer', version: 1 });
const editing = ref(false);
const editError = ref<ApiError | null>(null);

function openEdit(row: unknown): void {
  const target = row as UserView;
  editTarget.value = target;
  editForm.displayName = target.display_name;
  editForm.role = target.role;
  editForm.version = target.version;
  editError.value = null;
  editVisible.value = true;
}

async function saveEdit(): Promise<void> {
  if (editTarget.value === null) return;
  editing.value = true;
  editError.value = null;
  try {
    await request(`/users/${editTarget.value.id}`, {
      method: 'PATCH',
      body: {
        version: editForm.version,
        display_name: editForm.displayName,
        role: editForm.role,
      },
    });
    ElMessage.success('用户信息已更新');
    editVisible.value = false;
    await load();
  } catch (caught) {
    editError.value = caught as ApiError;
  } finally {
    editing.value = false;
  }
}

async function toggleStatus(row: unknown): Promise<void> {
  const target = row as UserView;
  const disabling = target.status === 'active';
  try {
    await ElMessageBox.confirm(
      disabling
        ? `停用后用户「${target.username}」将无法登录，已登录会话会被撤销；历史审计记录保留。确认停用？`
        : `确认启用用户「${target.username}」？`,
      disabling ? '停用用户' : '启用用户',
      { type: 'warning', confirmButtonText: '确认', cancelButtonText: '取消' },
    );
  } catch {
    return;
  }
  try {
    await request(`/users/${target.id}`, {
      method: 'PATCH',
      body: { version: target.version, status: disabling ? 'disabled' : 'active' },
    });
    ElMessage.success(disabling ? '用户已停用' : '用户已启用');
    await load();
  } catch (caught) {
    ElMessage.error(`操作失败：${(caught as ApiError).message}`);
  }
}

interface ResetForm {
  newPassword: string;
  confirmPassword: string;
  version: number;
}

const resetVisible = ref(false);
const resetTarget = ref<UserView | null>(null);
const resetForm = reactive<ResetForm>({ newPassword: '', confirmPassword: '', version: 1 });
const resetting = ref(false);
const resetError = ref<ApiError | null>(null);

function openReset(row: unknown): void {
  const target = row as UserView;
  resetTarget.value = target;
  resetForm.newPassword = '';
  resetForm.confirmPassword = '';
  resetForm.version = target.version;
  resetError.value = null;
  resetVisible.value = true;
}

async function resetPassword(): Promise<void> {
  if (resetTarget.value === null) return;
  if (resetForm.newPassword.length < 12) {
    ElMessage.warning('密码长度至少 12 位');
    return;
  }
  if (resetForm.newPassword !== resetForm.confirmPassword) {
    ElMessage.warning('两次输入的密码不一致');
    return;
  }
  resetting.value = true;
  resetError.value = null;
  try {
    await request(`/users/${resetTarget.value.id}`, {
      method: 'PATCH',
      body: {
        version: resetForm.version,
        new_password: resetForm.newPassword,
      },
    });
    ElMessage.success('密码已重置，该用户下次登录必须修改密码');
    resetVisible.value = false;
    await load();
  } catch (caught) {
    resetError.value = caught as ApiError;
  } finally {
    resetting.value = false;
  }
}

const sortedRows = computed(() => list.value?.items ?? []);
const total = computed(() => list.value?.total ?? 0);

onMounted(() => {
  void load();
});
</script>

<template>
  <div class="users-page">
    <AsyncState :state="state" :error="error">
      <div class="users-page__toolbar">
        <el-button type="primary" data-testid="create-user" @click="createVisible = true">
          创建用户
        </el-button>
      </div>
      <el-table :data="sortedRows" class="users-page__table" @sort-change="onSortChange">
        <el-table-column prop="username" label="用户名" min-width="140" sortable="custom" />
        <el-table-column prop="display_name" label="显示名称" min-width="140" sortable="custom" />
        <el-table-column prop="role" label="角色" width="100" sortable="custom">
          <template #default="{ row }">{{ label(ROLE_LABELS, row.role) }}</template>
        </el-table-column>
        <el-table-column prop="status" label="状态" width="90" sortable="custom">
          <template #default="{ row }">{{ label(USER_STATUS_LABELS, row.status) }}</template>
        </el-table-column>
        <el-table-column prop="last_login_at" label="最近登录" width="160">
          <template #default="{ row }">{{ formatDateTime(row.last_login_at) }}</template>
        </el-table-column>
        <el-table-column label="操作" width="220" fixed="right">
          <template #default="{ row }">
            <el-button link type="primary" @click="openEdit(row)">编辑</el-button>
            <el-button link type="primary" @click="openReset(row)">重置密码</el-button>
            <el-button
              link
              :type="row.status === 'active' ? 'danger' : 'success'"
              @click="toggleStatus(row)"
            >
              {{ row.status === 'active' ? '停用' : '启用' }}
            </el-button>
          </template>
        </el-table-column>
      </el-table>
      <PaginationBar
        v-model:page="page"
        v-model:page-size="pageSize"
        :total="total"
        @update:page="onPageChange"
        @update:page-size="onPageSizeChange"
      />
    </AsyncState>

    <el-dialog v-model="createVisible" title="创建用户" width="460px">
      <ErrorDetail v-if="createError" :error="createError" class="users-page__dialog-error" />
      <el-form label-width="96px">
        <el-form-item label="用户名">
          <el-input v-model="createForm.username" data-testid="new-username" />
        </el-form-item>
        <el-form-item label="显示名称">
          <el-input v-model="createForm.displayName" data-testid="new-display-name" />
        </el-form-item>
        <el-form-item label="角色">
          <el-select v-model="createForm.role" style="width: 100%">
            <el-option
              v-for="role in roles"
              :key="role"
              :value="role"
              :label="label(ROLE_LABELS, role)"
            />
          </el-select>
        </el-form-item>
        <el-form-item label="初始密码">
          <el-input
            v-model="createForm.password"
            type="password"
            show-password
            autocomplete="new-password"
            data-testid="new-password"
          />
        </el-form-item>
        <el-form-item label="确认密码">
          <el-input
            v-model="createForm.confirmPassword"
            type="password"
            show-password
            autocomplete="new-password"
            data-testid="new-confirm-password"
          />
        </el-form-item>
      </el-form>
      <p class="users-page__hint">
        密码长度至少 12 位，不能包含用户名，不能是常见弱密码；新用户首次登录必须修改密码
      </p>
      <template #footer>
        <el-button @click="createVisible = false">取消</el-button>
        <el-button
          type="primary"
          :loading="creating"
          data-testid="confirm-create"
          @click="createUser"
        >
          创建
        </el-button>
      </template>
    </el-dialog>

    <el-dialog v-model="editVisible" title="编辑用户" width="460px">
      <ErrorDetail v-if="editError" :error="editError" class="users-page__dialog-error" />
      <el-form label-width="96px">
        <el-form-item label="用户名">
          <span>{{ editTarget?.username }}</span>
        </el-form-item>
        <el-form-item label="显示名称">
          <el-input v-model="editForm.displayName" />
        </el-form-item>
        <el-form-item label="角色">
          <el-select v-model="editForm.role" style="width: 100%">
            <el-option
              v-for="role in roles"
              :key="role"
              :value="role"
              :label="label(ROLE_LABELS, role)"
            />
          </el-select>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="editVisible = false">取消</el-button>
        <el-button type="primary" :loading="editing" @click="saveEdit">保存</el-button>
      </template>
    </el-dialog>

    <el-dialog v-model="resetVisible" title="重置密码" width="460px">
      <ErrorDetail v-if="resetError" :error="resetError" class="users-page__dialog-error" />
      <el-form label-width="96px">
        <el-form-item label="新密码">
          <el-input
            v-model="resetForm.newPassword"
            type="password"
            show-password
            autocomplete="new-password"
          />
        </el-form-item>
        <el-form-item label="确认新密码">
          <el-input
            v-model="resetForm.confirmPassword"
            type="password"
            show-password
            autocomplete="new-password"
          />
        </el-form-item>
      </el-form>
      <p class="users-page__hint">
        密码长度至少 12 位，不能包含用户名，不能是常见弱密码；重置后该用户下次登录必须修改密码
      </p>
      <template #footer>
        <el-button @click="resetVisible = false">取消</el-button>
        <el-button type="primary" :loading="resetting" @click="resetPassword">重置密码</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<style scoped>
.users-page__toolbar {
  margin-bottom: 12px;
}
.users-page__dialog-error {
  margin-bottom: 12px;
}
.users-page__hint {
  margin: 0 0 0 96px;
  color: var(--warden-status-unknown);
  font-size: 12px;
}
</style>
