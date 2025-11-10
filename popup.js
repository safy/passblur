// PassBlur - Popup Script

document.addEventListener('DOMContentLoaded', function() {
  const toggleProtection = document.getElementById('toggleProtection');
  const rescanBtn = document.getElementById('rescanBtn');
  const keysCount = document.getElementById('keysCount');
  const statusText = document.getElementById('statusText');
  const notification = document.getElementById('notification');

  // Фильтры
  const filterCheckboxes = {
    emails: document.getElementById('filter-emails'),
    phones: document.getElementById('filter-phones'),
    creditcards: document.getElementById('filter-creditcards'),
    ssn: document.getElementById('filter-ssn'),
    apikeys: document.getElementById('filter-apikeys'),
    tokens: document.getElementById('filter-tokens')
  };

  // Загрузка текущего состояния
  loadStatus();
  loadFilters();

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
              showNotification(isEnabled ? 'Защита включена' : 'Защита отключена', 'success');
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
    rescanBtn.innerHTML = '<span class="spinner" style="margin-right: 0.5rem;"></span>Сканирование...';
    rescanBtn.disabled = true;

    chrome.tabs.query({ active: true, currentWindow: true }, function(tabs) {
      if (tabs[0]) {
        chrome.tabs.sendMessage(tabs[0].id, {
          action: 'rescan'
        }, function(response) {
          if (chrome.runtime.lastError) {
            showNotification('Ошибка: перезагрузите страницу', 'error');
            rescanBtn.innerHTML = originalText;
            rescanBtn.disabled = false;
          } else if (response && response.success) {
            keysCount.textContent = response.count || 0;
            showNotification(`Найдено ключей: ${response.count || 0}`, 'success');
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
    // Удаляем все badge классы
    statusText.classList.remove('badge-success', 'badge-destructive');
    
    if (isEnabled) {
      statusText.textContent = 'Активен';
      statusText.classList.add('badge-success');
    } else {
      statusText.textContent = 'Отключен';
      statusText.classList.add('badge-destructive');
    }
  }

  // Показать уведомление
  function showNotification(message, type = 'success') {
    notification.textContent = message;
    
    // Удаляем все toast классы типов
    notification.classList.remove('toast-success', 'toast-destructive');
    
    // Добавляем соответствующий класс типа
    if (type === 'success') {
      notification.classList.add('toast-success');
    } else if (type === 'error') {
      notification.classList.add('toast-destructive');
    }
    
    notification.classList.add('show');
    
    setTimeout(function() {
      notification.classList.remove('show');
    }, 2000);
  }

  // Обработчики фильтров
  Object.keys(filterCheckboxes).forEach(function(key) {
    filterCheckboxes[key].addEventListener('change', function() {
      saveFilters();
      applyFilters();
    });
  });

  // Загрузка настроек фильтров
  function loadFilters() {
    chrome.storage.sync.get(['detectionFilters'], function(result) {
      const filters = result.detectionFilters || {
        emails: true,
        phones: true,
        creditcards: true,
        ssn: true,
        apikeys: true,
        tokens: true
      };
      
      Object.keys(filterCheckboxes).forEach(function(key) {
        if (filterCheckboxes[key]) {
          filterCheckboxes[key].checked = filters[key] !== false;
        }
      });
    });
  }

  // Сохранение настроек фильтров
  function saveFilters() {
    const filters = {};
    Object.keys(filterCheckboxes).forEach(function(key) {
      filters[key] = filterCheckboxes[key].checked;
    });
    
    chrome.storage.sync.set({ detectionFilters: filters }, function() {
      console.log('Filters saved:', filters);
    });
  }

  // Применение фильтров к активной вкладке
  function applyFilters() {
    const filters = {};
    Object.keys(filterCheckboxes).forEach(function(key) {
      filters[key] = filterCheckboxes[key].checked;
    });

    chrome.tabs.query({ active: true, currentWindow: true }, function(tabs) {
      if (tabs[0]) {
        chrome.tabs.sendMessage(tabs[0].id, {
          action: 'updateFilters',
          filters: filters
        }, function(response) {
          if (chrome.runtime.lastError) {
            console.log('Content script not loaded yet');
          } else if (response && response.success) {
            showNotification('Фильтры обновлены', 'success');
            loadStatus();
          }
        });
      }
    });
  }

  // Слушаем сообщения о скопированных ключах
  chrome.runtime.onMessage.addListener(function(request, sender, sendResponse) {
    if (request.action === 'keyCopied') {
      // Можно добавить отображение уведомления в popup
      console.log('Key copied:', request.keyType);
    }
  });
});

