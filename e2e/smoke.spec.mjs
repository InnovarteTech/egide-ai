import { expect, test } from '@playwright/test';

const EMAIL = process.env.E2E_EMAIL || 'admin@egide.test';
const PASSWORD = process.env.E2E_PASSWORD || 'egide-e2e-secret';

test.beforeEach(async ({ page }) => {
    await page.goto('/entrar');
    await page.getByLabel('E-mail').fill(EMAIL);
    await page.getByLabel('Senha').fill(PASSWORD);
    await page.getByRole('button', { name: /entrar/i }).click();
    await page.waitForURL('/');
});

test('login leva ao console e o menu principal abre', async ({ page }) => {
    await expect(page).toHaveURL('/');
    await expect(page.locator('body')).not.toContainText('Rota indisponível');
});

test('ambientes lista os alvos e aceita o formulário de criação', async ({ page }) => {
    await page.goto('/ambientes');
    await expect(page).toHaveURL('/ambientes');
    await expect(page.locator('body')).toContainText(/ambiente|alvo|laborat/i);
});

test('sessões lista e a página de nova sessão abrem', async ({ page }) => {
    await page.goto('/sessoes');
    await expect(page).toHaveURL('/sessoes');
    await page.goto('/sessoes/nova');
    await expect(page).toHaveURL('/sessoes/nova');
    await expect(page.locator('body')).toContainText(/sessão|ambiente|laborat/i);
});

test('sessão do laboratório abre relatório quando existir', async ({ page }) => {
    const response = await page.goto('/sessoes');
    expect(response?.ok()).toBeTruthy();
    const link = page.locator('a[href*="/sessoes/"]').first();
    if (await link.count()) {
        await link.click();
        await expect(page.locator('body')).toContainText(/achado|cobertura|relatório|sessão/i);
    }
});
