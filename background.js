chrome.action.onClicked.addListener(async () => {
    const tab = await chrome.tabs.create({ url: "index.html" });
  });
  