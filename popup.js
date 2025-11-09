// PassBlur - Popup Script

document.addEventListener('DOMContentLoaded', function() {
  const toggleProtection = document.getElementById('toggleProtection');
  const rescanBtn = document.getElementById('rescanBtn');
  const keysCount = document.getElementById('keysCount');
  const statusText = document.getElementById('statusText');
  const notification = document.getElementById('notification');

  // Загрузка текущего состояния
  loadStatus();

  // Обработчик переключателя защиты
  toggleProtection.addEventListener('change', function() {
    const isEnabled = this.checked;
    
    chrome.storage.sync.set({ isEnabled: isEnabled }, function() {
      // Отправляем сообщение активной вкладке
      chrome.tabs.query({ active: true, currentWindow: true }, function(tabs) {
        if (tabs[0]) {
          chrome.tabs.sendMessage(tabs[0].id, {
            action: 'toggle',
            enabled: isEnabled
          }, function(response) {
            if (chrome.runtime.lastError) {
              console.log('Content script not loaded yet');
            } else {
              updateStatus(isEnabled);
              showNotification(isEnabled ? 'Защита включена' : 'Защита отключена');
              loadStatus();
            }
          });
        }
      });
    });
  });

  // Обработчик кнопки пересканирования
  rescanBtn.addEventListener('click', function() {
    const originalText = rescanBtn.innerHTML;
    rescanBtn.innerHTML = '<span class="spinner"></span> Сканирование...';
    rescanBtn.disabled = true;

    chrome.tabs.query({ active: true, currentWindow: true }, function(tabs) {
      if (tabs[0]) {
        chrome.tabs.sendMessage(tabs[0].id, {
          action: 'rescan'
        }, function(response) {
          if (chrome.runtime.lastError) {
            showNotification('Ошибка: перезагрузите страницу');
            rescanBtn.innerHTML = originalText;
            rescanBtn.disabled = false;
          } else if (response && response.success) {
            keysCount.textContent = response.count || 0;
            showNotification(`Найдено ключей: ${response.count || 0}`);
            rescanBtn.innerHTML = originalText;
            rescanBtn.disabled = false;
          }
        });
      }
    });
  });

  // Загрузка статуса
  function loadStatus() {
    chrome.storage.sync.get(['isEnabled'], function(result) {
      const isEnabled = result.isEnabled !== false;
      toggleProtection.checked = isEnabled;
      updateStatus(isEnabled);
    });

    // Получаем количество защищенных ключей с активной вкладки
    chrome.tabs.query({ active: true, currentWindow: true }, function(tabs) {
      if (tabs[0]) {
        chrome.tabs.sendMessage(tabs[0].id, {
          action: 'getStatus'
        }, function(response) {
          if (chrome.runtime.lastError) {
            keysCount.textContent = '-';
          } else if (response) {
            keysCount.textContent = response.count || 0;
            if (response.enabled !== undefined) {
              toggleProtection.checked = response.enabled;
              updateStatus(response.enabled);
            }
          }
        });
      }
    });
  }

  // Обновление отображения статуса
  function updateStatus(isEnabled) {
    if (isEnabled) {
      statusText.textContent = 'Активен';
      statusText.style.color = '#4CAF50';
    } else {
      statusText.textContent = 'Отключен';
      statusText.style.color = '#ff6b6b';
    }
  }

  // Показать уведомление
  function showNotification(message) {
    notification.textContent = message;
    notification.classList.add('show');
    
    setTimeout(function() {
      notification.classList.remove('show');
    }, 2000);
  }

  // Слушаем сообщения о скопированных ключах
  chrome.runtime.onMessage.addListener(function(request, sender, sendResponse) {
    if (request.action === 'keyCopied') {
      // Можно добавить отображение уведомления в popup
      console.log('Key copied:', request.keyType);
    }
  });
});

