import { describe, expect, it } from 'vitest';

import { REQUIREMENTS } from '@/api/generated/contracts';
import { REQUIREMENT_UI_SURFACES } from '@/features/devices/requirementTrace';

/**
 * 需求追踪表与生成注册表的一致性（M6T3）：REQUIREMENT_UI_SURFACES 必须
 * 恰好覆盖 51 条需求（capabilities.json 的生成物 REQUIREMENTS），新增或
 * 删除需求而未更新追踪表会使本套件失败。每条需求的承载面说明非空。
 */
describe('requirementTrace（M6T3 界面信息架构追踪表）', () => {
  it('追踪表键集合与 REQUIREMENTS 注册表完全一致', () => {
    expect(Object.keys(REQUIREMENT_UI_SURFACES).sort()).toEqual(
      Object.keys(REQUIREMENTS).sort(),
    );
  });

  it('覆盖全部 51 条原始需求', () => {
    expect(Object.keys(REQUIREMENT_UI_SURFACES)).toHaveLength(51);
  });

  it('每条需求都有非空承载面说明', () => {
    for (const [requirementId, surface] of Object.entries(REQUIREMENT_UI_SURFACES)) {
      expect(surface.trim().length, requirementId).toBeGreaterThan(0);
    }
  });

  it('操作类需求的承载面标注动态能力行或 launch 票据语义', () => {
    for (const [requirementId, requirement] of Object.entries(REQUIREMENTS)) {
      if (requirement.kind !== 'operation') {
        continue;
      }
      const surface = REQUIREMENT_UI_SURFACES[requirementId] ?? '';
      const markers = ['动态能力行', 'launch 一次性票据', '备份状态视图'];
      expect(markers.some((marker) => surface.includes(marker)), `${requirementId}: ${surface}`).toBe(
        true,
      );
    }
  });
});
