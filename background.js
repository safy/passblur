// PassBlur - Background Service Worker

chrome.runtime.onInstalled.addListener(() => {
  // Устанавливаем настройки по умолчанию
  chrome.storage.sync.set({
    isEnabled: true
  });
  
  console.log('PassBlur extension installed successfully');
});

// Слушаем сообщения от content script и popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'keyCopied') {
    // Можно добавить логику для отслеживания статистики
    console.log(`API key copied: ${request.keyType}`);
  }
  
  return true;
});

// Обработка обновления настроек
chrome.storage.onChanged.addListener((changes, namespace) => {
  if (namespace === 'sync' && changes.isEnabled) {
    // Отправляем сообщение всем вкладкам об изменении статуса
    chrome.tabs.query({}, (tabs) => {
      tabs.forEach(tab => {
        chrome.tabs.sendMessage(tab.id, {
          action: 'toggle',
          enabled: changes.isEnabled.newValue
        }).catch(() => {
          // Игнорируем ошибки для вкладок, где content script не загружен
        });
      });
    });
  }
});

