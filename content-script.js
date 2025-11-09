// PassBlur - Content Script
// Автоматическое обнаружение и размытие API ключей

(function() {
  'use strict';

  // Regex паттерны для различных типов API ключей
  const API_PATTERNS = {
    'OpenAI': /\b(sk-proj-[A-Za-z0-9_-]{40,}|sk-[A-Za-z0-9]{32,})\b/g,
    'AWS': /\b(AKIA[0-9A-Z]{16})\b/g,
    'Google API': /\b(A[Il]za[0-9A-Za-z_-]{30,})\b/g,
    'GitHub Token': /\b(gh[ps]_[A-Za-z0-9_]{36,255}|gho_[A-Za-z0-9_]{36,255})\b/g,
    'Stripe': /\b(sk_live_[0-9a-zA-Z]{24,}|sk_test_[0-9a-zA-Z]{24,}|pk_live_[0-9a-zA-Z]{24,}|pk_test_[0-9a-zA-Z]{24,})\b/g,
    'Slack': /\b(xox[pbarso]-[0-9A-Za-z-]{10,})\b/g,
    'Slack Webhook': /https:\/\/hooks\.slack\.com\/services\/[A-Z0-9]+\/[A-Z0-9]+\/[A-Za-z0-9]+/g,
    'Twilio': /\b(SK[a-f0-9]{32}|AC[a-f0-9]{32})\b/g,
    'Heroku': /\b([h|H][e|E][r|R][o|O][k|K][u|U].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12})\b/gi,
    'Mailgun': /\b(key-[0-9a-zA-Z]{32})\b/g,
    'Firebase': /\b(A[Il]za[0-9A-Za-z\\-_]{30,})\b/g,
    'JWT': /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g,
    'Generic API Key': /\b(api[_-]?key[_-]?[=:]\s*['"]?[A-Za-z0-9_\-]{20,}['"]?)\b/gi,
    'Bearer Token': /\b(Bearer\s+[A-Za-z0-9\-._~+\/]+=*)\b/gi
  };

  let isEnabled = true;
  let blurredElements = new Set();
  let observer = null;
  let processingElements = new Set(); // Элементы в процессе обработки
  let processedNodes = new WeakSet(); // WeakSet для отслеживания обработанных узлов
  let operationCount = 0; // Счетчик операций
  let lastResetTime = Date.now(); // Время последнего сброса

  // Проверка настроек при загрузке
  chrome.storage.sync.get(['isEnabled'], function(result) {
    isEnabled = result.isEnabled !== false;
    if (isEnabled) {
      init();
    }
  });

  // Инициализация
  function init() {
    // Сканируем сразу ОДИН раз
    scanPage();
    // Больше НЕ делаем автоматические повторные сканирования - они создают цикл
    // setTimeout(() => scanPage(), 1000); // ОТКЛЮЧЕНО
    // setTimeout(() => scanPage(), 3000); // ОТКЛЮЧЕНО
    observeDOMChanges();
    setupMessageListener();
    setupClickInterceptor();
  }

  // Перехват кликов по кнопкам которые могут открывать модалки
  function setupClickInterceptor() {
    document.addEventListener('click', function(e) {
      if (!isEnabled) return;
      
      const target = e.target;
      
      // Проверяем клики по кнопкам/ссылкам которые могут открывать API ключи
      if (target.matches && (
        target.matches('button') || 
        target.matches('[role="button"]') ||
        target.matches('a') ||
        target.closest('button') ||
        target.closest('[role="button"]')
      )) {
        // Запускаем ТОЛЬКО сканирование input полей (не весь scanPage!)
        setTimeout(() => {
          if (isEnabled) scanInputFields();
        }, 10);
        setTimeout(() => {
          if (isEnabled) scanInputFields();
        }, 50);
        setTimeout(() => {
          if (isEnabled) scanInputFields();
        }, 150);
        setTimeout(() => {
          if (isEnabled) scanInputFields();
        }, 300);
      }
    }, true); // Используем capture phase для более раннего срабатывания
  }

  // Основная функция сканирования страницы
  function scanPage() {
    if (!isEnabled) return;
    
    // Сканируем текстовые узлы
    scanTextNodes();
    // Сканируем input поля
    scanInputFields();
  }

  // Сканирование текстовых узлов
  function scanTextNodes() {
    if (!isEnabled) return;
    
    const walker = document.createTreeWalker(
      document.body,
      NodeFilter.SHOW_TEXT,
      {
        acceptNode: function(node) {
          // Пропускаем скрипты, стили и уже обработанные элементы
          const parent = node.parentElement;
          if (!parent) return NodeFilter.FILTER_REJECT;
          
          const tagName = parent.tagName.toLowerCase();
          if (tagName === 'script' || tagName === 'style' || tagName === 'noscript') {
            return NodeFilter.FILTER_REJECT;
          }
          
          if (parent.classList.contains('passblur-wrapper') || parent.classList.contains('passblur-input-wrapper')) {
            return NodeFilter.FILTER_REJECT;
          }
          
          return NodeFilter.FILTER_ACCEPT;
        }
      }
    );

    const nodesToProcess = [];
    let currentNode;
    
    while (currentNode = walker.nextNode()) {
      nodesToProcess.push(currentNode);
    }

    nodesToProcess.forEach(node => processTextNode(node));
  }

  // Сканирование input полей, textarea и других элементов формы
  function scanInputFields() {
    if (!isEnabled) return;
    
    const inputs = document.querySelectorAll('input[type="text"], input[type="password"], input:not([type]), textarea, pre, code');
    
    inputs.forEach(input => {
      // Пропускаем уже обработанные
      if (input.classList.contains('passblur-input-processed') || 
          input.closest('.passblur-input-wrapper')) {
        return;
      }

      let value = '';
      if (input.tagName.toLowerCase() === 'input' || input.tagName.toLowerCase() === 'textarea') {
        value = input.value || input.getAttribute('value') || input.placeholder || '';
      } else {
        value = input.textContent || '';
      }

      if (!value) return;

      // УМНАЯ ПРОВЕРКА: это действительно API ключ?
      if (isLikelyApiKey(value)) {
        processInputField(input);
      }
    });
  }

  // Умное определение - является ли строка API ключом
  function isLikelyApiKey(value) {
    // Игнорируем короткие строки (названия типа "cursor", "vision")
    if (value.length < 20) {
      return false;
    }

    // Игнорируем обычные слова и предложения
    if (/^[a-zA-Z\s\-_]+$/.test(value) && value.length < 30) {
      return false;
    }

    // Проверяем на конкретные паттерны ключей
    for (const [keyType, pattern] of Object.entries(API_PATTERNS)) {
      // Сбрасываем lastIndex для глобальных regex
      pattern.lastIndex = 0;
      
      if (pattern.test(value)) {
        // Дополнительная проверка длины для найденного совпадения
        const matches = value.match(pattern);
        if (matches && matches[0] && matches[0].length >= 20) {
          return true;
        }
      }
    }

    return false;
  }

  // Обработка input поля с API ключом
  function processInputField(input) {
    // ПРОВЕРКА #1: элемент уже обработан?
    if (input.classList.contains('passblur-input-processed')) {
      return; // Уже обработан, выходим
    }
    
    // ПРОВЕРКА #2: элемент в процессе обработки?
    if (processingElements.has(input)) {
      return; // Уже обрабатывается, выходим
    }
    
    // ПРОВЕРКА #3: наши собственные элементы?
    if (input.classList.contains('passblur-input-overlay') || 
        input.closest('.passblur-input-overlay') ||
        input.hasAttribute('data-passblur-original')) {
      return; // Это наш элемент, не трогаем
    }
    
    // КРИТИЧНО: Помечаем в Set ДО любых действий
    processingElements.add(input);
    
    // Помечаем класс КАК МОЖНО РАНЬШЕ
    input.classList.add('passblur-input-processed');
    
    // Получаем значение и определяем тип ключа
    const value = input.value || input.textContent || '';
    
    // Еще одна проверка - это действительно ключ?
    if (!isLikelyApiKey(value)) {
      input.classList.remove('passblur-input-processed'); // Снимаем метку
      processingElements.delete(input); // Удаляем из Set
      return;
    }
    
    let keyType = 'Unknown';
    
    for (const [type, pattern] of Object.entries(API_PATTERNS)) {
      pattern.lastIndex = 0;
      if (pattern.test(value)) {
        keyType = type;
        break;
      }
    }

    // ПРОВЕРКА: Если элемент слишком большой (контейнер), ищем реальный элемент с токеном внутри
    const elementHeight = input.offsetHeight || input.clientHeight || 0;
    const elementWidth = input.offsetWidth || input.clientWidth || 0;
    
    // Если высота > 200px или ширина > 800px - это скорее всего контейнер, а не само поле
    if (elementHeight > 200 || elementWidth > 800) {
      // Ищем внутри контейнера реальный элемент с токеном
      const innerElements = input.querySelectorAll('input, textarea, code, span, div');
      let found = false;
      
      for (const innerEl of innerElements) {
        // Пропускаем уже обработанные
        if (innerEl.classList.contains('passblur-input-processed')) {
          continue;
        }
        
        const innerValue = innerEl.value || innerEl.textContent || '';
        if (innerValue.length >= 20 && isLikelyApiKey(innerValue)) {
          // Нашли реальный элемент с ключом
          found = true;
          processInputField(innerEl);
          break; // Обработали один, хватит
        }
      }
      
      if (found) {
        input.classList.remove('passblur-input-processed'); // Снимаем с контейнера
        processingElements.delete(input); // Удаляем из Set
        return; // Выходим, не обрабатываем контейнер
      }
      
      // Если ничего не нашли, тоже удаляем из Set
      processingElements.delete(input);
    }

    // Сохраняем оригинальное значение
    input.setAttribute('data-passblur-original', value);
    input.setAttribute('data-passblur-type', keyType);

    // Применяем blur прямо к input полю
    const originalStyle = input.getAttribute('style') || '';
    input.setAttribute('data-passblur-style', originalStyle);
    
    // Ограничиваем размеры чтобы не создавать огромные блоки
    const maxHeight = Math.min(elementHeight || 100, 100);
    const maxWidth = Math.min(elementWidth || 500, 600);
    
    input.style.cssText = originalStyle + `
      filter: blur(6px) !important;
      -webkit-filter: blur(6px) !important;
      color: transparent !important;
      text-shadow: 0 0 8px rgba(138, 43, 226, 0.8) !important;
      cursor: pointer !important;
      user-select: none !important;
      -webkit-user-select: none !important;
      max-height: ${maxHeight}px !important;
      overflow: hidden !important;
    `;

    // Создаем overlay для клика и tooltip (с ограничением размера)
    const overlay = document.createElement('div');
    overlay.className = 'passblur-input-overlay';
    overlay.setAttribute('data-key-type', keyType);
    
    // Ограничиваем размеры overlay
    const overlayWidth = Math.min(input.offsetWidth || 500, 600);
    const overlayHeight = Math.min(input.offsetHeight || 50, 100);
    
    overlay.style.cssText = `
      position: absolute !important;
      top: ${input.offsetTop}px !important;
      left: ${input.offsetLeft}px !important;
      width: ${overlayWidth}px !important;
      height: ${overlayHeight}px !important;
      background: transparent !important;
      cursor: pointer !important;
      z-index: 2147483647 !important;
      display: flex !important;
      align-items: center !important;
      justify-content: center !important;
      pointer-events: all !important;
    `;

    // Создаем tooltip
    const tooltip = document.createElement('span');
    tooltip.className = 'passblur-tooltip';
    tooltip.style.cssText = `
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%) !important;
      color: white !important;
      padding: 6px 12px !important;
      border-radius: 6px !important;
      font-size: 12px !important;
      white-space: nowrap !important;
      opacity: 0 !important;
      transition: opacity 0.3s ease !important;
      pointer-events: none !important;
      box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3) !important;
    `;
    tooltip.textContent = `🔒 ${keyType} - Click to copy`;
    overlay.appendChild(tooltip);

    // Вставляем overlay рядом с input
    input.parentNode.insertBefore(overlay, input.nextSibling);

    // Показываем tooltip при наведении
    overlay.addEventListener('mouseenter', function() {
      tooltip.style.opacity = '1';
    });
    
    overlay.addEventListener('mouseleave', function() {
      tooltip.style.opacity = '0';
    });

    // Обработчик клика для копирования
    overlay.addEventListener('click', function(e) {
      e.preventDefault();
      e.stopPropagation();
      const valueToCopy = input.getAttribute('data-passblur-original') || input.value || input.textContent || '';
      copyToClipboard(valueToCopy, overlay);
    });

    // Также блокируем клики на само input поле
    input.addEventListener('click', function(e) {
      e.preventDefault();
      e.stopPropagation();
      const valueToCopy = input.getAttribute('data-passblur-original') || input.value || input.textContent || '';
      copyToClipboard(valueToCopy, overlay);
    });

    // Запрещаем выделение и изменение
    input.addEventListener('focus', function(e) {
      e.target.blur();
    });

    input.addEventListener('select', function(e) {
      e.preventDefault();
    });

    blurredElements.add(input);
    blurredElements.add(overlay);
    
    // Удаляем из processingElements только в конце
    processingElements.delete(input);
  }

  // Обработка текстового узла
  function processTextNode(textNode) {
    if (!isEnabled) return;
    
    // АВАРИЙНАЯ ЗАЩИТА: проверка частоты операций
    operationCount++;
    const now = Date.now();
    if (now - lastResetTime > 1000) {
      // Каждую секунду сбрасываем счетчик
      if (operationCount > 500) { // Увеличено со 100 до 500
        console.warn('PassBlur: Too many operations (>500/sec), temporarily disabling for 5 seconds');
        isEnabled = false;
        setTimeout(() => {
          isEnabled = true;
          operationCount = 0;
          console.log('PassBlur: Re-enabled after cooldown');
        }, 5000);
        return;
      }
      operationCount = 0;
      lastResetTime = now;
    }
    
    // Проверка: этот узел уже обработан?
    if (processedNodes.has(textNode)) {
      return;
    }
    
    // Проверка: родитель уже обработан?
    if (textNode.parentElement && textNode.parentElement.classList.contains('passblur-wrapper')) {
      return;
    }
    
    // Помечаем узел как обработанный
    processedNodes.add(textNode);
    
    const text = textNode.textContent;
    let foundKeys = [];

    // Проверяем текст на все паттерны
    for (const [keyType, pattern] of Object.entries(API_PATTERNS)) {
      pattern.lastIndex = 0; // Сброс для глобальных regex
      const matches = [...text.matchAll(pattern)];
      matches.forEach(match => {
        const matchedText = match[0];
        
        // УМНАЯ ПРОВЕРКА: игнорируем короткие совпадения (названия)
        if (matchedText.length >= 20) {
          foundKeys.push({
            type: keyType,
            value: matchedText,
            index: match.index
          });
        }
      });
    }

    if (foundKeys.length === 0) return;

    // Сортируем найденные ключи по индексу
    foundKeys.sort((a, b) => a.index - b.index);

    // Создаем новую структуру с размытыми элементами
    const parent = textNode.parentElement;
    if (!parent) return;

    const fragment = document.createDocumentFragment();
    let lastIndex = 0;

    foundKeys.forEach(key => {
      // Добавляем текст до ключа
      if (key.index > lastIndex) {
        const beforeText = text.substring(lastIndex, key.index);
        fragment.appendChild(document.createTextNode(beforeText));
      }

      // Создаем размытый элемент для ключа
      const blurredElement = createBlurredElement(key.value, key.type);
      if (!blurredElement) {
        // Если не создали элемент (лимит превышен), вставляем оригинальный текст
        fragment.appendChild(document.createTextNode(key.value));
        return; // Используем return вместо continue в forEach
      }
      fragment.appendChild(blurredElement);
      blurredElements.add(blurredElement);

      lastIndex = key.index + key.value.length;
    });

    // Добавляем оставшийся текст
    if (lastIndex < text.length) {
      const afterText = text.substring(lastIndex);
      fragment.appendChild(document.createTextNode(afterText));
    }

    // Заменяем оригинальный текстовый узел
    parent.replaceChild(fragment, textNode);
  }

  // Создание размытого элемента
  function createBlurredElement(keyValue, keyType) {
    // Проверка что мы не создаем слишком много элементов
    const existingWrappers = document.querySelectorAll('.passblur-wrapper').length;
    if (existingWrappers > 200) { // Увеличено с 50 до 200
      console.warn('PassBlur: Too many wrappers (>200), stopping to prevent performance issues');
      isEnabled = false;
      setTimeout(() => {
        console.log('PassBlur: Wrapper limit reset');
      }, 3000);
      return null;
    }
    
    const wrapper = document.createElement('span');
    wrapper.className = 'passblur-wrapper';
    wrapper.setAttribute('data-key-type', keyType);
    wrapper.setAttribute('data-original', keyValue);

    const blurredSpan = document.createElement('span');
    blurredSpan.className = 'passblur-blurred';
    blurredSpan.textContent = keyValue;

    const tooltip = document.createElement('span');
    tooltip.className = 'passblur-tooltip';
    tooltip.textContent = `🔒 ${keyType} - Click to copy`;

    wrapper.appendChild(blurredSpan);
    wrapper.appendChild(tooltip);

    // Обработчик клика для копирования
    wrapper.addEventListener('click', function(e) {
      e.preventDefault();
      e.stopPropagation();
      copyToClipboard(keyValue, wrapper);
    });

    return wrapper;
  }

  // Копирование в буфер обмена
  function copyToClipboard(text, element) {
    navigator.clipboard.writeText(text).then(() => {
      showCopyNotification(element);
      
      // Отправляем сообщение в popup о копировании
      chrome.runtime.sendMessage({
        action: 'keyCopied',
        keyType: element.getAttribute('data-key-type')
      });
    }).catch(err => {
      console.error('Failed to copy:', err);
      
      // Fallback метод
      const textarea = document.createElement('textarea');
      textarea.value = text;
      textarea.style.position = 'fixed';
      textarea.style.opacity = '0';
      document.body.appendChild(textarea);
      textarea.select();
      document.execCommand('copy');
      document.body.removeChild(textarea);
      
      showCopyNotification(element);
    });
  }

  // Показать уведомление о копировании
  function showCopyNotification(element) {
    const notification = document.createElement('div');
    notification.className = 'passblur-notification';
    notification.textContent = '✓ Copied!';
    
    const rect = element.getBoundingClientRect();
    notification.style.position = 'fixed';
    notification.style.left = rect.left + 'px';
    notification.style.top = (rect.top - 30) + 'px';
    
    document.body.appendChild(notification);
    
    setTimeout(() => {
      notification.classList.add('passblur-notification-fade');
      setTimeout(() => notification.remove(), 300);
    }, 1500);
  }

  // Наблюдение за изменениями DOM
  function observeDOMChanges() {
    if (observer) {
      observer.disconnect();
    }

    observer = new MutationObserver((mutations) => {
      if (!isEnabled) return;
      
      // Фильтруем мутации - игнорируем наши собственные изменения
      const relevantMutations = mutations.filter(mutation => {
        // Игнорируем мутации в наших элементах
        if (mutation.target.classList && 
            (mutation.target.classList.contains('passblur-input-overlay') ||
             mutation.target.classList.contains('passblur-wrapper') ||
             mutation.target.classList.contains('passblur-input-processed'))) {
          return false;
        }
        
        // Игнорируем добавление наших overlay
        if (mutation.type === 'childList' && mutation.addedNodes.length > 0) {
          for (const node of mutation.addedNodes) {
            if (node.nodeType === Node.ELEMENT_NODE && 
                (node.classList.contains('passblur-input-overlay') ||
                 node.classList.contains('passblur-notification'))) {
              return false;
            }
          }
        }
        
        return true;
      });
      
      if (relevantMutations.length === 0) return;
      
      // НЕМЕДЛЕННАЯ обработка для новых input полей
      relevantMutations.forEach((mutation) => {
        if (mutation.type === 'childList') {
          mutation.addedNodes.forEach((node) => {
            if (node.nodeType === Node.ELEMENT_NODE) {
              // Пропускаем наши элементы
              if (node.classList && 
                  (node.classList.contains('passblur-input-overlay') ||
                   node.classList.contains('passblur-wrapper'))) {
                return;
              }
              
              // Проверяем сам узел
              if (node.matches && node.matches('input, textarea, pre, code')) {
                checkAndProcessInput(node);
              }
              // Проверяем детей
              const inputs = node.querySelectorAll ? node.querySelectorAll('input, textarea, pre, code') : [];
              inputs.forEach(input => {
                if (!input.classList.contains('passblur-input-processed')) {
                  checkAndProcessInput(input);
                }
              });
            }
          });
        }
        
        // Отслеживаем изменения атрибута value (но не для обработанных элементов)
        if (mutation.type === 'attributes' && mutation.attributeName === 'value') {
          const target = mutation.target;
          if (target.matches && target.matches('input, textarea') &&
              !target.classList.contains('passblur-input-processed')) {
            checkAndProcessInput(target);
          }
        }
      });

      // НЕ делаем полное сканирование в Observer - это создает цикл!
      // Обработка новых элементов выше уже достаточна
    });

    observer.observe(document.body, {
      childList: true,
      subtree: true,
      attributes: true,
      attributeFilter: ['value']
    });
  }

  // Быстрая проверка и обработка одного input
  function checkAndProcessInput(input) {
    if (!isEnabled) return;
    
    // СТРОГИЕ проверки перед обработкой
    if (!input || !input.tagName) return;
    
    // Пропускаем уже обработанные
    if (input.classList.contains('passblur-input-processed')) {
      return;
    }
    
    // Пропускаем наши элементы
    if (input.classList.contains('passblur-input-overlay') ||
        input.classList.contains('passblur-wrapper') ||
        input.closest('.passblur-input-wrapper') ||
        input.closest('.passblur-input-overlay') ||
        input.hasAttribute('data-passblur-original')) {
      return;
    }

    let value = '';
    if (input.tagName.toLowerCase() === 'input' || input.tagName.toLowerCase() === 'textarea') {
      value = input.value || input.getAttribute('value') || input.placeholder || '';
    } else {
      value = input.textContent || '';
    }

    if (!value) return;

    // УМНАЯ проверка
    if (isLikelyApiKey(value)) {
      try {
        processInputField(input);
      } catch (e) {
        console.error('PassBlur: Error processing input', e);
        // Снимаем метку в случае ошибки
        input.classList.remove('passblur-input-processed');
      }
    }
  }

  // Слушатель сообщений от popup
  function setupMessageListener() {
    chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
      if (request.action === 'toggle') {
        isEnabled = request.enabled;
        if (isEnabled) {
          scanPage();
          if (!observer) observeDOMChanges();
        } else {
          removeAllBlurs();
          if (observer) observer.disconnect();
        }
        sendResponse({ success: true });
      } else if (request.action === 'rescan') {
        removeAllBlurs();
        scanPage();
        sendResponse({ success: true, count: blurredElements.size });
      } else if (request.action === 'getStatus') {
        sendResponse({ 
          enabled: isEnabled, 
          count: blurredElements.size 
        });
      }
      return true;
    });
  }

  // Удалить все размытия
  function removeAllBlurs() {
    // Удаляем размытие текстовых элементов
    document.querySelectorAll('.passblur-wrapper').forEach(wrapper => {
      try {
        const textNode = document.createTextNode(wrapper.getAttribute('data-original') || '');
        if (wrapper.parentNode) {
          wrapper.parentNode.replaceChild(textNode, wrapper);
        }
      } catch (e) {
        console.error('PassBlur: Error removing wrapper', e);
      }
    });
    
    // Удаляем размытие input полей - восстанавливаем стили
    document.querySelectorAll('.passblur-input-processed').forEach(input => {
      try {
        input.classList.remove('passblur-input-processed');
        const originalStyle = input.getAttribute('data-passblur-style') || '';
        input.style.cssText = originalStyle;
        input.removeAttribute('data-passblur-original');
        input.removeAttribute('data-passblur-type');
        input.removeAttribute('data-passblur-style');
      } catch (e) {
        console.error('PassBlur: Error removing input blur', e);
      }
    });
    
    // Удаляем все overlay
    document.querySelectorAll('.passblur-input-overlay').forEach(overlay => {
      try {
        overlay.remove();
      } catch (e) {
        console.error('PassBlur: Error removing overlay', e);
      }
    });
    
    blurredElements.clear();
    processingElements.clear();
    processedNodes = new WeakSet(); // Создаем новый WeakSet
    operationCount = 0;
    lastResetTime = Date.now();
  }

})();

