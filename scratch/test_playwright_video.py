import asyncio
from playwright.async_api import async_playwright

async def main():
    async with async_playwright() as p:
        try:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context(
                record_video_dir="scratch/test_video",
                record_video_size={"width": 1280, "height": 720}
            )
            page = await context.new_page()
            await page.goto("http://localhost:5173/")
            await page.wait_for_timeout(2000)
            await context.close()
            await browser.close()
            print("Playwright video recorded successfully!")
        except Exception as e:
            print("Error:", e)

if __name__ == "__main__":
    asyncio.run(main())
