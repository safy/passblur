// PassBlur - Content Script
// Автоматическое обнаружение и размытие чувствительных данных:
// - API Keys (OpenAI, AWS, GitHub, Stripe, etc.)
// - Authentication Tokens (JWT, Bearer, OAuth)
// - Email addresses
// - Phone numbers
// - Credit card numbers
// - Social Security Numbers (SSN)

console.log('🔒 PassBlur: Content script starting...');

(function() {
  'use strict';
  
  console.log('🔒 PassBlur: Script initialized!');

  // Regex паттерны для различных типов данных
  const DETECTION_PATTERNS = {
    // API Keys and Tokens
    apikeys: {
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
      'Generic API Key': /\b(api[_-]?key[_-]?[=:]\s*['"]?[A-Za-z0-9_\-]{20,}['"]?)\b/gi
    },
    // Authentication Tokens
    tokens: {
      'JWT': /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g,
      'Bearer Token': /\b(Bearer\s+[A-Za-z0-9\-._~+\/]+=*)\b/gi,
      'OAuth Token': /\b(oauth[_-]?token[_-]?[=:]\s*['"]?[A-Za-z0-9_\-]{20,}['"]?)\b/gi
    },
    // Emails
    emails: {
      'Email': /\b([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b/g
    },
    // Phone Numbers (более строгие паттерны)
    phones: {
      // Российские номера: +7 (XXX) XXX-XX-XX, 8 (XXX) XXX-XX-XX
      'Phone (RU)': /(?:\+7|8)[\s\-]?\(?\d{3}\)?[\s\-]?\d{3}[\s\-]?\d{2}[\s\-]?\d{2}\b/g,
      // Международные с кодом страны: +XX XXX XXX XXXX (минимум 10 цифр)
      'Phone (Intl +)': /\+\d{1,3}[\s\-]?\(?\d{2,4}\)?[\s\-]?\d{2,4}[\s\-]?\d{2,4}[\s\-]?\d{0,4}\b/g,
      // US/Canada: (XXX) XXX-XXXX или XXX-XXX-XXXX
      'Phone (US)': /\(?\d{3}\)?[\s\-]?\d{3}[\s\-]?\d{4}\b/g
    },
    // Credit Cards
    creditcards: {
      'Visa': /\b(4[0-9]{3}[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4})\b/g,
      'MasterCard': /\b(5[1-5][0-9]{2}[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4})\b/g,
      'AmEx': /\b(3[47][0-9]{2}[-\s]?[0-9]{6}[-\s]?[0-9]{5})\b/g,
      'Discover': /\b(6(?:011|5[0-9]{2})[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4})\b/g,
      'Generic Card': /\b([0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4})\b/g
    },
    // SSN
    ssn: {
      'SSN': /\b([0-9]{3}[-\s]?[0-9]{2}[-\s]?[0-9]{4})\b/g
    }
  };

  // Старый API_PATTERNS для обратной совместимости
  const API_PATTERNS = {
    ...DETECTION_PATTERNS.apikeys,
    ...DETECTION_PATTERNS.tokens
  };

  let isEnabled = true;
  let blurredElements = new Set();
  let observer = null;
  let processingElements = new Set(); // Элементы в процессе обработки
  let processedNodes = new WeakSet(); // WeakSet для отслеживания обработанных узлов
  let operationCount = 0; // Счетчик операций
  let lastResetTime = Date.now(); // Время последнего сброса
  
  // Фильтры обнаружения
  let detectionFilters = {
    emails: true,
    phones: true,
    creditcards: true,
    ssn: true,
    apikeys: true,
    tokens: true
  };

  // Проверка настроек при загрузке
  chrome.storage.sync.get(['isEnabled', 'detectionFilters'], function(result) {
    isEnabled = result.isEnabled !== false;
    if (result.detectionFilters) {
      detectionFilters = { ...detectionFilters, ...result.detectionFilters };
    }
    
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
    setupAltKeyToggle();
    setupAutofillBlur(); // Отслеживаем автозаполнение и размываем
  }

  // Настройка переключения видимости по Alt + Hover
  function setupAltKeyToggle() {
    let altPressed = false;

    // Отслеживаем нажатие Alt
    document.addEventListener('keydown', function(e) {
      if (e.key === 'Alt' && !altPressed) {
        e.preventDefault(); // Предотвращаем активацию меню браузера
        e.stopPropagation();
        altPressed = true;
      }
    }, true); // Используем capture phase

    // Отслеживаем отпускание Alt
    document.addEventListener('keyup', function(e) {
      if (e.key === 'Alt' && altPressed) {
        e.preventDefault();
        e.stopPropagation();
        altPressed = false;
        // Скрываем все элементы при отпускании Alt
        hideAllRevealedContent();
      }
    }, true); // Используем capture phase

    // Обрабатываем потерю фокуса окна
    window.addEventListener('blur', function() {
      if (altPressed) {
        altPressed = false;
        hideAllRevealedContent();
      }
    });

    // Обработчики для текстовых элементов (.passblur-wrapper)
    document.addEventListener('mouseover', function(e) {
      if (!altPressed || !isEnabled) return;

      const wrapper = e.target.closest('.passblur-wrapper');
      if (wrapper) {
        showElementContent(wrapper);
      }
    }, true);

    document.addEventListener('mouseout', function(e) {
      if (!isEnabled) return;

      const wrapper = e.target.closest('.passblur-wrapper');
      if (wrapper) {
        hideElementContent(wrapper);
      }
    }, true);

    // Обработчики для input полей
    document.addEventListener('mouseover', function(e) {
      if (!altPressed || !isEnabled) return;

      if (e.target.classList.contains('passblur-input-processed')) {
        showInputContent(e.target);
      }
    }, true);

    document.addEventListener('mouseout', function(e) {
      if (!isEnabled) return;

      if (e.target.classList.contains('passblur-input-processed')) {
        hideInputContent(e.target);
      }
    }, true);

    // Обработчики для iframe элементов
    document.addEventListener('mouseover', function(e) {
      if (!altPressed || !isEnabled) return;

      const iframe = e.target.closest('.passblur-iframe-processed');
      
      if (iframe) {
        showIframeContent(iframe);
      }
    }, true);

    document.addEventListener('mouseout', function(e) {
      if (!isEnabled) return;

      const iframe = e.target.closest('.passblur-iframe-processed');
      
      if (iframe) {
        hideIframeContent(iframe);
      }
    }, true);
  }

  // Показать содержимое iframe
  function showIframeContent(iframe) {
    iframe.style.filter = 'none';
    iframe.style.webkitFilter = 'none';
    iframe.setAttribute('data-revealed', 'true');

    // Скрываем индикатор
    const indicator = iframe.parentElement.querySelector('.passblur-iframe-indicator');
    if (indicator) {
      indicator.style.opacity = '0';
    }
  }

  // Скрыть содержимое iframe
  function hideIframeContent(iframe) {
    if (iframe.getAttribute('data-revealed') !== 'true') return;

    iframe.style.setProperty('filter', 'blur(5px)', 'important');
    iframe.style.setProperty('-webkit-filter', 'blur(5px)', 'important');
    iframe.removeAttribute('data-revealed');

    // Показываем индикатор
    const indicator = iframe.parentElement.querySelector('.passblur-iframe-indicator');
    if (indicator) {
      indicator.style.opacity = '0.9';
    }
  }

  // Показать содержимое конкретного текстового элемента
  function showElementContent(wrapper) {
    const blurredSpan = wrapper.querySelector('.passblur-blurred');
    if (blurredSpan) {
      blurredSpan.style.filter = 'none';
      blurredSpan.style.webkitFilter = 'none';
      blurredSpan.style.color = 'inherit';
      blurredSpan.style.textShadow = 'none';
      wrapper.setAttribute('data-revealed', 'true');
    }
  }

  // Скрыть содержимое конкретного текстового элемента
  function hideElementContent(wrapper) {
    const blurredSpan = wrapper.querySelector('.passblur-blurred');
    if (blurredSpan && wrapper.getAttribute('data-revealed') === 'true') {
      blurredSpan.style.filter = '';
      blurredSpan.style.webkitFilter = '';
      blurredSpan.style.color = '';
      blurredSpan.style.textShadow = '';
      wrapper.removeAttribute('data-revealed');
    }
  }

  // Показать содержимое конкретного input поля
  function showInputContent(input) {
    input.setAttribute('data-revealed', 'true');

    // Для полей карт с text-security
    if (input.classList.contains('passblur-card-tracked')) {
      input.classList.add('passblur-card-revealed');
    } else {
      // Для обычных полей
      input.style.filter = 'none';
      input.style.webkitFilter = 'none';
      input.style.color = 'inherit';
      input.style.textShadow = 'none';
      input.style.textSecurity = 'none';
      input.style.webkitTextSecurity = 'none';

      // Скрываем overlay для этого input
      const overlay = input.nextElementSibling;
      if (overlay && overlay.classList.contains('passblur-input-overlay')) {
        overlay.style.display = 'none';
      }
    }
  }

  // Скрыть содержимое конкретного input поля
  function hideInputContent(input) {
    if (input.getAttribute('data-revealed') !== 'true') return;

    input.removeAttribute('data-revealed');

    // Проверяем, является ли это поле карты с text-security
    if (input.classList.contains('passblur-card-tracked')) {
      // Убираем класс revealed - CSS вернет точки
      input.classList.remove('passblur-card-revealed');
    } else if (input.classList.contains('passblur-input-processed')) {
      // Для обычных обработанных полей с blur
      const originalStyle = input.getAttribute('data-passblur-style') || '';
      input.style.cssText = originalStyle + `
        filter: blur(6px) !important;
        -webkit-filter: blur(6px) !important;
        color: transparent !important;
        text-shadow: 0 0 8px rgba(138, 43, 226, 0.8) !important;
      `;

      // Показываем overlay обратно
      const overlay = input.nextElementSibling;
      if (overlay && overlay.classList.contains('passblur-input-overlay')) {
        overlay.style.display = '';
      }
    }
  }

  // Скрыть все раскрытые элементы
  function hideAllRevealedContent() {
    // Скрываем все текстовые элементы
    document.querySelectorAll('.passblur-wrapper[data-revealed="true"]').forEach(wrapper => {
      hideElementContent(wrapper);
    });

    // Скрываем все input поля
    document.querySelectorAll('.passblur-input-processed[data-revealed="true"]').forEach(input => {
      hideInputContent(input);
    });

    // Скрываем все iframe элементы
    document.querySelectorAll('.passblur-iframe-processed[data-revealed="true"]').forEach(iframe => {
      hideIframeContent(iframe);
    });
  }

  // Настройка размытия автозаполненных данных
  function setupAutofillBlur() {
    console.log('🔒 PassBlur: setupAutofillBlur called, creditcards filter:', detectionFilters.creditcards);
    console.log('🔒 PassBlur: isEnabled:', isEnabled);
    console.log('🔒 PassBlur: All filters:', detectionFilters);
    
    // Проверяем фильтр кредитных карт
    if (!detectionFilters.creditcards) {
      console.log('🔒 PassBlur: ⚠️ Credit cards filter is DISABLED!');
      return;
    }

    console.log('🔒 PassBlur: ✓ Credit cards filter is ENABLED');

    // Вспомогательная функция для быстрой проверки номера карты по значению
    function hasCardNumber(value) {
      if (!value || value.length === 0) return false;
      const digits = value.replace(/\D/g, '');
      // Номер карты: 13-19 цифр
      const isCard = digits.length >= 13 && digits.length <= 19;
      if (isCard) {
        console.log('🔒 PassBlur: [hasCardNumber] ✓✓✓ CARD NUMBER FOUND! Digits:', digits.length, 'Value:', value.substring(0, 20));
      }
      return isCard;
    }

    // Вспомогательная функция для получения значения из input (включая Stripe элементы)
    function getInputValue(input) {
      if (!input) return '';
      
      // Проверяем стандартное значение
      let value = input.value || '';
      
      // Если значение пустое, проверяем другие источники
      if (!value || value.length === 0) {
        // Проверяем атрибут value
        value = input.getAttribute('value') || '';
        
        // Проверяем текстовое содержимое
        if (!value || value.length === 0) {
          value = input.textContent || input.innerText || '';
        }
        
        // Проверяем дочерние элементы (для Stripe контейнеров)
        if (!value || value.length === 0) {
          const childInputs = input.querySelectorAll('input');
          for (const childInput of childInputs) {
            const childValue = childInput.value || childInput.getAttribute('value') || '';
            if (childValue && childValue.length > 0) {
              value = childValue;
              break;
            }
          }
        }
      }
      
      return value;
    }

    // Специальная функция для поиска и размытия Stripe элементов и любых элементов с номером карты
    function checkAndBlurStripeElements() {
      if (!isEnabled) return;
      
      // КРИТИЧНО: Проверяем видимые элементы в формах оплаты на наличие номера карты
      // Ограничиваем проверку формами оплаты для производительности
      const paymentAreas = document.querySelectorAll('form, [role="dialog"], .modal, [class*="payment"], [class*="billing"], [class*="card-form"], [class*="stripe"], [class*="card"]');
      const searchScope = paymentAreas.length > 0 ? paymentAreas : [document.body];
      
      let cardNumberFound = false;
      
      searchScope.forEach(scope => {
        // Ищем только видимые элементы внутри области поиска
        const candidates = scope.querySelectorAll('div, span, p, label, td, th, li, input, button');
        
        for (const el of candidates) {
          // Пропускаем уже обработанные
          if (el.classList.contains('passblur-stripe-processed') || 
              el.classList.contains('passblur-input-processed')) {
            continue;
          }
          
          // Пропускаем скрытые элементы
          const style = window.getComputedStyle(el);
          if (style.display === 'none' || 
              style.visibility === 'hidden' || 
              style.opacity === '0' ||
              el.offsetParent === null) {
            continue;
          }
          
          // ИСКЛЮЧЕНИЯ: Проверяем, не является ли это полем имени/адреса
          if (el.tagName === 'INPUT') {
            const inputName = (el.name || '').toLowerCase();
            const inputId = (el.id || '').toLowerCase();
            const inputPlaceholder = (el.placeholder || '').toLowerCase();
            const inputAttrs = `${inputName} ${inputId} ${inputPlaceholder}`;
            
            // Ключевые слова для исключений
            const excludeKeywords = ['name', 'fname', 'lname', 'firstname', 'lastname', 'fullname',
              'address', 'street', 'city', 'state', 'zip', 'postal', 'country', 'region',
              'email', 'phone', 'tel', 'mobile'];
            
            if (excludeKeywords.some(keyword => inputAttrs.includes(keyword))) {
              console.log('🔒 PassBlur: Skipping excluded field:', inputAttrs.substring(0, 50));
              continue; // Пропускаем это поле
            }
          }
          
          // Получаем видимый текст элемента (только прямой текст, без рекурсии)
          let text = '';
          if (el.tagName === 'INPUT') {
            text = getInputValue(el);
          } else {
            // Для других элементов берем textContent
            text = el.textContent || el.innerText || '';
          }
          
          // Проверяем, есть ли номер карты в тексте
          if (text.length > 10 && hasCardNumber(text)) {
            // Проверяем, не является ли это частью уже обработанного контейнера
            const parent = el.closest('.passblur-stripe-processed');
            if (parent) {
              continue; // Уже обработан родительский контейнер
            }
            
            console.log('🔒 PassBlur: ✓✓✓ CARD NUMBER FOUND IN ELEMENT! Tag:', el.tagName, 'Text:', text.substring(0, 30));
            
            // Размываем элемент
            if (el.tagName === 'INPUT') {
              applyBlurToFilledInput(el);
            } else {
              applyBlurToElement(el);
            }
            cardNumberFound = true;
            
            // Также размываем родительский контейнер, если он есть
            if (el.parentElement && !el.parentElement.classList.contains('passblur-stripe-processed')) {
              applyBlurToElement(el.parentElement);
            }
          }
        }
      });
      
      if (cardNumberFound) {
        console.log('🔒 PassBlur: Card number found and blurred in payment forms!');
        return; // Уже нашли и размыли, можно выходить
      }
      
      // Ищем все Stripe контейнеры
      const stripeContainers = document.querySelectorAll('.StripeElement, [class*="StripeElement"], [class*="_PrivateStripeElement"], [class*="stripe-card-form"], [class*="stripe"], div[class*="card"], div[class*="payment"]');
      
      console.log('🔒 PassBlur: Checking', stripeContainers.length, 'Stripe containers...');
      
      stripeContainers.forEach(container => {
        // Пропускаем уже обработанные
        if (container.classList.contains('passblur-stripe-processed')) {
          return;
        }
        
        // Получаем весь видимый текст из контейнера (включая все дочерние элементы)
        let visibleText = '';
        
        // Проверяем textContent
        visibleText = container.textContent || container.innerText || '';
        
        // Если не нашли, проверяем все дочерние элементы
        if (!visibleText || visibleText.length === 0) {
          const allChildren = container.querySelectorAll('*');
          allChildren.forEach(child => {
            const childText = child.textContent || child.innerText || '';
            if (childText && childText.length > 0) {
              visibleText += ' ' + childText;
            }
          });
        }
        
        // Проверяем, есть ли в тексте номер карты
        if (hasCardNumber(visibleText)) {
          console.log('🔒 PassBlur: ✓✓✓ STRIPE CONTAINER WITH CARD NUMBER FOUND! Text:', visibleText.substring(0, 30), 'Blurring container...');
          
          // Помечаем как обработанный
          container.classList.add('passblur-stripe-processed');
          
          // Применяем размытие к контейнеру с overlay
          applyBlurToElement(container);
          
          console.log('🔒 PassBlur: STRIPE CONTAINER BLURRED!');
        }
        
        // Также проверяем все input элементы внутри контейнера
        const inputs = container.querySelectorAll('input');
        inputs.forEach(input => {
          if (input.classList.contains('passblur-input-processed')) {
            return;
          }
          
          const inputValue = getInputValue(input);
          if (hasCardNumber(inputValue)) {
            console.log('🔒 PassBlur: ✓✓✓ CARD NUMBER IN STRIPE INPUT FOUND!');
            applyBlurToFilledInput(input);
          }
        });
      });
      
      
      // ФИНАЛЬНАЯ ПРОВЕРКА: проходим по текстовым узлам в формах оплаты
      // Это последняя попытка найти номер карты, если он не был найден выше
      const paymentFormsForText = document.querySelectorAll('form, [role="dialog"], .modal, [class*="payment"], [class*="billing"], [class*="card-form"], [class*="stripe"]');
      const textSearchScope = paymentFormsForText.length > 0 ? paymentFormsForText : [document.body];
      
      textSearchScope.forEach(scope => {
        const walker = document.createTreeWalker(
          scope,
          NodeFilter.SHOW_TEXT,
          {
            acceptNode: function(node) {
              // Пропускаем скрытые элементы
              let parent = node.parentElement;
              while (parent && parent !== scope) {
                const style = window.getComputedStyle(parent);
                if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') {
                  return NodeFilter.FILTER_REJECT;
                }
                // Пропускаем уже обработанные
                if (parent.classList.contains('passblur-stripe-processed')) {
                  return NodeFilter.FILTER_REJECT;
                }
                parent = parent.parentElement;
              }
              return NodeFilter.FILTER_ACCEPT;
            }
          }
        );
        
        let textNode;
        let textNodeCount = 0;
        while (textNode = walker.nextNode()) {
          textNodeCount++;
          const text = textNode.textContent || '';
          
          // Проверяем только достаточно длинные текстовые узлы
          if (text.length > 10 && hasCardNumber(text)) {
            const parentElement = textNode.parentElement;
            if (parentElement && !parentElement.classList.contains('passblur-stripe-processed')) {
              console.log('🔒 PassBlur: ✓✓✓ TEXT NODE WITH CARD NUMBER FOUND! Text:', text.substring(0, 30), 'Parent:', parentElement.tagName);
              
              // Размываем родительский элемент с overlay
              applyBlurToElement(parentElement);
              
              console.log('🔒 PassBlur: TEXT NODE PARENT BLURRED!');
              break; // Нашли и размыли, выходим из цикла
            }
          }
        }
        
        if (textNodeCount > 0) {
          console.log('🔒 PassBlur: Checked', textNodeCount, 'text nodes in scope for card numbers');
        }
      });
    }

    // Храним последние состояния полей для отслеживания изменений
    const fieldStates = new Map();

    // НЕМЕДЛЕННАЯ проверка всех полей при загрузке
    console.log('🔒 PassBlur: Performing IMMEDIATE check for pre-filled fields...');
    const allInputs = document.querySelectorAll('input[type="text"], input:not([type]), input[type="tel"], input[type="number"], input[inputmode="numeric"], input[inputmode="decimal"], input[class*="Stripe"], input[class*="stripe"], input[class*="_PrivateStripeElement"]');
    console.log('🔒 PassBlur: Found', allInputs.length, 'input fields on page');
    
    allInputs.forEach(input => {
      // Получаем значение через расширенную функцию
      const inputValue = getInputValue(input);
      
      // Проверяем значение в input.value
      if (inputValue && inputValue.length > 0) {
        console.log('🔒 PassBlur: Found pre-filled input:', input.name || input.id, 'value length:', inputValue.length, 'value:', inputValue.substring(0, 20));
        
        // ПРЯМАЯ ПРОВЕРКА: если значение похоже на номер карты - размываем сразу!
        if (hasCardNumber(inputValue)) {
          console.log('🔒 PassBlur: ✓✓✓ PRE-FILLED CARD NUMBER DETECTED DIRECTLY! Applying blur immediately!');
          applyBlurToFilledInput(input);
        }
        // Обычная проверка
        else if (isCardInputField(input)) {
          console.log('🔒 PassBlur: ✓✓✓ PRE-FILLED CARD FIELD DETECTED! Applying blur immediately!');
          applyBlurToFilledInput(input);
        }
      }
      
      // Инициализируем состояние
      fieldStates.set(input, input.value || '');
    });
    
    // СПЕЦИАЛЬНАЯ ПРОВЕРКА: Stripe контейнеры
    console.log('🔒 PassBlur: Checking Stripe containers...');
    checkAndBlurStripeElements();
    
    // АГРЕССИВНАЯ ПРОВЕРКА: ищем номер карты в элементах форм оплаты
    console.log('🔒 PassBlur: Performing aggressive card number search...');
    const paymentForms = document.querySelectorAll('form, [role="dialog"], .modal, [class*="payment"], [class*="billing"]');
    const searchAreas = paymentForms.length > 0 ? paymentForms : [document.body];
    
    searchAreas.forEach(area => {
      const allElementsWithText = area.querySelectorAll('*');
      allElementsWithText.forEach(el => {
      // Пропускаем скрипты, стили и уже обработанные
      if (el.tagName === 'SCRIPT' || el.tagName === 'STYLE' || el.tagName === 'NOSCRIPT' ||
          el.classList.contains('passblur-stripe-processed') || 
          el.classList.contains('passblur-input-processed')) {
        return;
      }
      
      // Получаем текст
      let text = '';
      if (el.tagName === 'INPUT') {
        text = getInputValue(el);
        
        // ИСКЛЮЧЕНИЯ для input
        const inputName = (el.name || '').toLowerCase();
        const inputId = (el.id || '').toLowerCase();
        const inputAttrs = `${inputName} ${inputId}`;
        const excludeKeywords = ['name', 'address', 'street', 'city', 'state', 'zip', 'postal', 'country', 'email', 'phone'];
        if (excludeKeywords.some(kw => inputAttrs.includes(kw))) {
          return; // Пропускаем
        }
      } else {
        text = el.textContent || '';
      }
      
      // Проверяем только прямой текст элемента (без детей)
      if (el.children.length > 0 && el.tagName !== 'INPUT') {
        return; // Пропускаем контейнеры, проверяем только листовые элементы
      }
      
        // Проверяем на номер карты
        if (text.length > 10 && hasCardNumber(text)) {
          console.log('🔒 PassBlur: ✓✓✓ AGGRESSIVE CHECK: Card number found in', el.tagName, 'text:', text.substring(0, 30));
          
          if (el.tagName === 'INPUT') {
            applyBlurToFilledInput(el);
          } else {
            applyBlurToElement(el);
          }
        }
      });
    });
    
    // Также проверяем через небольшие задержки (на случай, если Stripe загружается асинхронно)
    setTimeout(() => {
      console.log('🔒 PassBlur: Delayed check for Stripe containers...');
      checkAndBlurStripeElements();
    }, 100);
    
    setTimeout(() => {
      console.log('🔒 PassBlur: Second delayed check for Stripe containers...');
      checkAndBlurStripeElements();
    }, 500);
    
    setTimeout(() => {
      console.log('🔒 PassBlur: Third delayed check for Stripe containers...');
      checkAndBlurStripeElements();
    }, 1000);
    
    setTimeout(() => {
      console.log('🔒 PassBlur: Fourth delayed check for Stripe containers...');
      checkAndBlurStripeElements();
    }, 2000);

    // СУПЕР-ЧАСТАЯ проверка в первые 5 секунд (когда автозаполнение наиболее вероятно)
    let checkCount = 0;
    const maxFastChecks = 100; // 100 проверок по 20ms = 2 секунды супер-быстрой проверки
    
    const superFastInterval = setInterval(() => {
      if (!isEnabled) return;
      
      checkCount++;
      
      // РАСШИРЕННЫЙ список типов полей для проверки!
      const inputs = document.querySelectorAll('input[type="text"], input:not([type]), input[type="tel"], input[type="number"], input[inputmode="numeric"], input[inputmode="decimal"], input[class*="Stripe"], input[class*="stripe"], input[class*="_PrivateStripeElement"]');
      
      inputs.forEach(input => {
        const currentValue = getInputValue(input) || '';
        const previousValue = fieldStates.get(input) || '';
        
        // Проверяем ВСЕ поля с значением - не только те, что определены как карточные!
        if (currentValue !== previousValue && currentValue.length > 0) {
          // ПРЯМАЯ ПРОВЕРКА: если значение похоже на номер карты - размываем сразу!
          // ЭТО ПЕРВЫЙ ПРИОРИТЕТ - проверяем ДО всех остальных проверок!
          if (hasCardNumber(currentValue)) {
            console.log('🔒 PassBlur: [SUPER-FAST] ✓✓✓ CARD NUMBER DETECTED DIRECTLY! Value:', currentValue.substring(0, 20), 'Applying blur IMMEDIATELY');
            applyBlurToFilledInput(input);
          }
          // Если поле изменилось - проверяем, это карточное поле?
          else if (isCardInputField(input)) {
            console.log('🔒 PassBlur: [SUPER-FAST] Card field detected with value, length:', currentValue.length);
            applyBlurToFilledInput(input); // БЕЗ ЗАДЕРЖКИ!
          }
        }
        
        // Обновляем состояние
        fieldStates.set(input, input.value || '');
      });
      
      // Проверяем Stripe контейнеры в супер-быстром режиме
      checkAndBlurStripeElements();
      
      // Останавливаем супер-быструю проверку через 2 секунды
      if (checkCount >= maxFastChecks) {
        clearInterval(superFastInterval);
        console.log('🔒 PassBlur: Switching to normal speed checks');
      }
    }, 20); // СУПЕР-БЫСТРО: каждые 20ms первые 2 секунды!

    // Периодическая проверка полей на автозаполнение - ОЧЕНЬ ЧАСТАЯ для мгновенного размытия
    setInterval(() => {
      if (!isEnabled) return;
      
      // РАСШИРЕННЫЙ список типов полей для проверки!
      const inputs = document.querySelectorAll('input[type="text"], input:not([type]), input[type="tel"], input[type="number"], input[inputmode="numeric"], input[inputmode="decimal"], input[class*="Stripe"], input[class*="stripe"], input[class*="_PrivateStripeElement"]');
      
      inputs.forEach(input => {
        const currentValue = getInputValue(input) || '';
        const previousValue = fieldStates.get(input) || '';
        
        // Проверяем ВСЕ поля с изменившимся значением
        if (currentValue !== previousValue && currentValue.length > 0) {
          // ПРЯМАЯ ПРОВЕРКА: если значение похоже на номер карты - размываем сразу!
          // ЭТО ПЕРВЫЙ ПРИОРИТЕТ - проверяем ДО всех остальных проверок!
          if (hasCardNumber(currentValue)) {
            console.log('🔒 PassBlur: ✓✓✓ CARD NUMBER DETECTED DIRECTLY in interval! Value:', currentValue.substring(0, 20), 'Applying blur IMMEDIATELY');
          applyBlurToFilledInput(input);
          }
          // Проверяем, это карточное поле?
          else if (isCardInputField(input)) {
            console.log('🔒 PassBlur: Field value changed, length:', currentValue.length, '- applying blur!');
            applyBlurToFilledInput(input); // БЕЗ ЗАДЕРЖКИ!
          }
        }
        
        // Обновляем состояние
        fieldStates.set(input, input.value || '');
      });
      
      // Проверяем Stripe контейнеры в обычном режиме
      checkAndBlurStripeElements();
    }, 50); // Проверяем каждые 50ms (было 200ms) - в 4 раза чаще!

    // НЕ сканируем сразу! Только при автозаполнении
    // scanForCardFields(); // ОТКЛЮЧЕНО

    // Отслеживаем автозаполнение через change event - МГНОВЕННО!
    document.addEventListener('change', function(e) {
      if (!isEnabled) return;
      const input = e.target;
      
      console.log('🔒 PassBlur: Change event on:', input.tagName, input.name, input.value?.length);
      
      if (input.tagName === 'INPUT' && input.value) {
        // Получаем значение через расширенную функцию (для Stripe элементов)
        const inputValue = getInputValue(input);
        
        // ПРЯМАЯ ПРОВЕРКА: если значение похоже на номер карты - размываем сразу!
        // ЭТО ПЕРВЫЙ ПРИОРИТЕТ - проверяем ДО всех остальных проверок!
        if (hasCardNumber(inputValue)) {
          console.log('🔒 PassBlur: ✓✓✓ CARD NUMBER DETECTED DIRECTLY in change event! Value:', inputValue.substring(0, 20), 'Applying blur IMMEDIATELY');
          applyBlurToFilledInput(input);
          return; // ВАЖНО: выходим сразу, не проверяем дальше!
        }
        
        // Обычная проверка через isCardInputField (только если это НЕ номер карты)
        if (isCardInputField(input)) {
          console.log('🔒 PassBlur: Detected card field autofill via change, applying blur IMMEDIATELY');
          applyBlurToFilledInput(input); // БЕЗ ЗАДЕРЖКИ!
        }
      }
      
      // Также проверяем Stripe контейнеры при изменении
      setTimeout(() => checkAndBlurStripeElements(), 50);
    }, true);

    // Отслеживаем через input event (вставка из буфера или автозаполнение) - МГНОВЕННО!
    document.addEventListener('input', function(e) {
      if (!isEnabled) return;
      const input = e.target;
      
      if (input.tagName === 'INPUT' && input.value) {
        // Получаем значение через расширенную функцию (для Stripe элементов)
        const inputValue = getInputValue(input);
        
        // ПРЯМАЯ ПРОВЕРКА: если значение похоже на номер карты - размываем сразу!
        // ЭТО ПЕРВЫЙ ПРИОРИТЕТ - проверяем ДО всех остальных проверок!
        if (hasCardNumber(inputValue)) {
          console.log('🔒 PassBlur: ✓✓✓ CARD NUMBER DETECTED DIRECTLY in input event! Value:', inputValue.substring(0, 20), 'Applying blur IMMEDIATELY');
          applyBlurToFilledInput(input);
          return; // ВАЖНО: выходим сразу, не проверяем дальше!
        }
        
        // Обычная проверка через isCardInputField (только если это НЕ номер карты)
        if (isCardInputField(input)) {
        // Проверяем - это вставка или автозаполнение (большое изменение за раз)
          const valueLength = inputValue.length;
        if (valueLength > 10) {
            console.log('🔒 PassBlur: Detected autofill/paste via input (length > 10), applying blur IMMEDIATELY');
            applyBlurToFilledInput(input); // БЕЗ ЗАДЕРЖКИ!
        }
      }
      }
      
      // Также проверяем Stripe контейнеры при вводе
      setTimeout(() => checkAndBlurStripeElements(), 50);
    }, true);

    // Отслеживаем потерю фокуса - Chrome иногда заполняет при blur - МГНОВЕННО!
    document.addEventListener('blur', function(e) {
      if (!isEnabled) return;
      const input = e.target;
      
      if (input.tagName === 'INPUT' && input.value && !input.classList.contains('passblur-input-processed')) {
        // Получаем значение через расширенную функцию (для Stripe элементов)
        const inputValue = getInputValue(input);
        
        // ПРЯМАЯ ПРОВЕРКА: если значение похоже на номер карты - размываем сразу!
        // ЭТО ПЕРВЫЙ ПРИОРИТЕТ - проверяем ДО всех остальных проверок!
        if (hasCardNumber(inputValue)) {
          console.log('🔒 PassBlur: ✓✓✓ CARD NUMBER DETECTED DIRECTLY in blur event! Value:', inputValue.substring(0, 20), 'Applying blur IMMEDIATELY');
          applyBlurToFilledInput(input);
          return; // ВАЖНО: выходим сразу, не проверяем дальше!
        }
        
        // Обычная проверка через isCardInputField (только если это НЕ номер карты)
        if (isCardInputField(input)) {
          console.log('🔒 PassBlur: Blur event, checking if autofilled, value length:', inputValue.length);
          if (inputValue.length > 10) {
            console.log('🔒 PassBlur: Field has long value on blur, applying blur IMMEDIATELY');
            applyBlurToFilledInput(input); // БЕЗ ЗАДЕРЖКИ!
          }
        }
      }
    }, true);

    // Агрессивное отслеживание через MutationObserver для полей - МГНОВЕННО!
    const autofillObserver = new MutationObserver((mutations) => {
      mutations.forEach((mutation) => {
        if (mutation.type === 'attributes' && mutation.target.tagName === 'INPUT') {
          const input = mutation.target;
          
          if (input.value && input.value.length > 0 && !input.classList.contains('passblur-input-processed')) {
            // Получаем значение через расширенную функцию (для Stripe элементов)
            const inputValue = getInputValue(input);
            
            // ПРЯМАЯ ПРОВЕРКА: если значение похоже на номер карты - размываем сразу!
            // ЭТО ПЕРВЫЙ ПРИОРИТЕТ - проверяем ДО всех остальных проверок!
            if (hasCardNumber(inputValue)) {
              console.log('🔒 PassBlur: ✓✓✓ CARD NUMBER DETECTED DIRECTLY via MutationObserver! Value:', inputValue.substring(0, 20), 'Applying blur IMMEDIATELY');
              applyBlurToFilledInput(input);
              return; // ВАЖНО: выходим сразу, не проверяем дальше!
            }
            
            // Обычная проверка (только если это НЕ номер карты)
            if (isCardInputField(input) && inputValue.length > 10) {
            console.log('🔒 PassBlur: Detected value via MutationObserver:', input.name);
              applyBlurToFilledInput(input); // БЕЗ ЗАДЕРЖКИ!
            }
          }
        }
        
        // Также проверяем изменения в DOM структуре (для Stripe контейнеров)
        if (mutation.type === 'childList' || mutation.type === 'characterData') {
          // Проверяем Stripe контейнеры при изменении DOM
          checkAndBlurStripeElements();
        }
      });
    });

    // Наблюдаем за всеми input полями и изменениями DOM (для Stripe контейнеров)
    autofillObserver.observe(document.body, {
      attributes: true,
      attributeFilter: ['value'],
      childList: true, // Отслеживаем добавление/удаление элементов
      characterData: true, // Отслеживаем изменения текстового содержимого
      subtree: true
    });

    // Дополнительная защита: отслеживаем фокус на полях
    document.addEventListener('focus', function(e) {
      if (!isEnabled) return;
      const input = e.target;
      
      if (input.tagName === 'INPUT' && input.value && !input.classList.contains('passblur-input-processed')) {
        // Получаем значение через расширенную функцию (для Stripe элементов)
        const inputValue = getInputValue(input);
        
        // ПРЯМАЯ ПРОВЕРКА: если значение похоже на номер карты - размываем сразу!
        if (hasCardNumber(inputValue)) {
          console.log('🔒 PassBlur: ✓✓✓ CARD NUMBER DETECTED DIRECTLY on focus! Applying blur IMMEDIATELY');
          applyBlurToFilledInput(input);
          return;
        }
        
        // Обычная проверка
        if (isCardInputField(input)) {
          // Если поле УЖЕ заполнено при фокусе - возможно автозаполнение произошло
          if (inputValue.length > 10) {
            console.log('🔒 PassBlur: Field already filled on focus - applying blur');
            applyBlurToFilledInput(input); // БЕЗ ЗАДЕРЖКИ!
          }
        }
      }
    }, true);

    // КРИТИЧНО: Отслеживаем animationstart - браузеры часто генерируют при автозаполнении!
    document.addEventListener('animationstart', function(e) {
      if (!isEnabled) return;
      const input = e.target;
      
      if (input.tagName === 'INPUT' && input.value && !input.classList.contains('passblur-input-processed')) {
        // Получаем значение через расширенную функцию (для Stripe элементов)
        const inputValue = getInputValue(input);
        
        // ПРЯМАЯ ПРОВЕРКА: если значение похоже на номер карты - размываем сразу!
        if (hasCardNumber(inputValue)) {
          console.log('🔒 PassBlur: ✓✓✓ CARD NUMBER DETECTED DIRECTLY via animationstart! Applying blur INSTANTLY');
          applyBlurToFilledInput(input);
          return;
        }
        
        // Обычная проверка
        if (isCardInputField(input)) {
          // Проверяем через requestAnimationFrame для синхронизации с рендерингом
          requestAnimationFrame(() => {
            const currentValue = getInputValue(input);
            if (currentValue && currentValue.length > 10) {
              console.log('🔒 PassBlur: Detected autofill via animationstart - applying blur INSTANTLY');
              applyBlurToFilledInput(input); // МГНОВЕННО!
            }
          });
        }
      }
    }, true);

    // КРИТИЧЕСКИ ВАЖНО: Сканируем Stripe iframe сразу и периодически!
    console.log('🔒 PassBlur: Starting Stripe iframe scanning...');
    
    // Сканируем сразу
    scanForPaymentIframes();
    
    // Повторяем сканирование каждые 500ms первые 5 секунд (Stripe загружается асинхронно)
    let iframeScanCount = 0;
    const maxIframeScans = 10; // 10 раз по 500ms = 5 секунд
    
    const iframeScanInterval = setInterval(() => {
      if (!isEnabled) return;
      
      iframeScanCount++;
      scanForPaymentIframes();
      
      if (iframeScanCount >= maxIframeScans) {
        clearInterval(iframeScanInterval);
        console.log('🔒 PassBlur: Stripe iframe scanning completed');
      }
    }, 500);

    // Продолжаем сканировать периодически (раз в 2 секунды)
    setInterval(() => {
      if (!isEnabled) return;
      scanForPaymentIframes();
    }, 2000);
  }

  // Функция больше не используется - размытие только при автозаполнении через события

  // Применить размытие к заполненному полю - МГНОВЕННО И АГРЕССИВНО!
  function applyBlurToFilledInput(input) {
    if (input.classList.contains('passblur-input-processed')) {
      return; // Уже обработано
    }

    console.log('🔒 PassBlur: Applying IMMEDIATE blur to filled input:', input.name, input.value?.substring(0, 4) + '...');

    // КРИТИЧЕСКИ ВАЖНО: Помечаем СРАЗУ!
    input.classList.add('passblur-input-processed');

    // Сохраняем оригинальные стили
    const originalStyle = input.getAttribute('style') || '';
    input.setAttribute('data-passblur-style', originalStyle);

    // Применяем СИЛЬНОЕ размытие МГНОВЕННО!
    input.style.cssText = originalStyle + `
      filter: blur(8px) !important;
      -webkit-filter: blur(8px) !important;
      color: transparent !important;
      text-shadow: 0 0 10px rgba(138, 43, 226, 0.9) !important;
      cursor: pointer !important;
      user-select: none !important;
      -webkit-user-select: none !important;
      pointer-events: auto !important;
    `;

    console.log('🔒 PassBlur: STRONG blur applied IMMEDIATELY!');

    // Обработчик клика для показа
    input.addEventListener('click', function(e) {
      e.preventDefault();
      e.stopPropagation();
      // Alt + hover уже обработан в setupAltKeyToggle
    });
  }

  // Применить размытие к любому элементу (не только input) с overlay
  function applyBlurToElement(element) {
    if (!element || element.classList.contains('passblur-stripe-processed')) {
      return; // Уже обработано
    }

    console.log('🔒 PassBlur: Applying blur to element:', element.tagName, element.className);

    // Помечаем как обработанный
    element.classList.add('passblur-stripe-processed');

    // Сохраняем оригинальные стили
    const originalStyle = element.getAttribute('style') || '';
    element.setAttribute('data-passblur-style', originalStyle);

    // Убеждаемся, что элемент имеет position: relative для overlay
    const computedStyle = window.getComputedStyle(element);
    if (computedStyle.position === 'static') {
      element.style.position = 'relative';
    }

    // Применяем размытие к самому элементу
    element.style.cssText = originalStyle + `
      filter: blur(8px) !important;
      -webkit-filter: blur(8px) !important;
      position: relative !important;
    `;

    // Создаем overlay поверх элемента для дополнительной защиты
    const overlay = document.createElement('div');
    overlay.className = 'passblur-input-overlay';
    overlay.style.cssText = `
      position: absolute !important;
      top: 0 !important;
      left: 0 !important;
      width: 100% !important;
      height: 100% !important;
      background: rgba(138, 43, 226, 0.15) !important;
      backdrop-filter: blur(6px) !important;
      -webkit-backdrop-filter: blur(6px) !important;
      border-radius: 4px !important;
      cursor: pointer !important;
      z-index: 2147483647 !important;
      display: flex !important;
      align-items: center !important;
      justify-content: center !important;
      pointer-events: all !important;
      transition: all 0.3s ease !important;
    `;

    // Добавляем overlay как дочерний элемент
    element.appendChild(overlay);

    console.log('🔒 PassBlur: Element blurred with overlay!');
  }

  // Сканирование и размытие iframe от Stripe/платёжных систем
  function scanForPaymentIframes() {
    if (!isEnabled || !detectionFilters.creditcards) return;

    const allIframes = document.querySelectorAll('iframe');
    console.log('🔒 PassBlur: [scanForPaymentIframes] Found', allIframes.length, 'iframe elements');
    
    let foundCount = 0;
    allIframes.forEach(iframe => {
      // Пропускаем уже обработанные
      if (iframe.classList.contains('passblur-iframe-processed')) {
        return;
      }

      // Проверяем атрибуты iframe
      const src = (iframe.src || '').toLowerCase();
      const name = (iframe.name || '').toLowerCase();
      const id = (iframe.id || '').toLowerCase();
      const title = (iframe.title || '').toLowerCase();
      const className = (iframe.className || '').toLowerCase();

      // Ключевые слова для платежных iframe
      const paymentKeywords = [
        'stripe', 'payment', 'card', 'checkout', 
        'billing', 'paypal', 'square', 'braintree',
        'adyen', 'карт', 'оплат', 'js.stripe.com',
        '__privatestripeframe', 'cardnumber', '__privatestripe'
      ];

      const allText = `${src} ${name} ${id} ${title} ${className}`;
      
      console.log('🔒 PassBlur: [scanForPaymentIframes] Checking iframe:', {
        src: src.substring(0, 50),
        name: name.substring(0, 30),
        id, title, className: className.substring(0, 30)
      });
      
      if (paymentKeywords.some(keyword => allText.includes(keyword))) {
        console.log('🔒 PassBlur: ✓✓✓ PAYMENT IFRAME DETECTED! Applying blur...');
        applyBlurToIframe(iframe);
        foundCount++;
      }
    });
    
    if (foundCount > 0) {
      console.log('🔒 PassBlur: [scanForPaymentIframes] Blurred', foundCount, 'payment iframes');
    }
  }

  // Применить размытие к iframe
  function applyBlurToIframe(iframe) {
    iframe.classList.add('passblur-iframe-processed');

    // Применяем размытие по умолчанию
    iframe.style.setProperty('filter', 'blur(6px)', 'important');
    iframe.style.setProperty('-webkit-filter', 'blur(6px)', 'important');
    iframe.style.setProperty('transition', 'filter 0.3s ease', 'important');

    // Создаем кнопку-глазик для просмотра
    const viewBtn = document.createElement('button');
    viewBtn.className = 'passblur-iframe-view-button';
    viewBtn.textContent = '👁️';
    viewBtn.title = 'Удерживайте для просмотра';
    viewBtn.type = 'button';
    viewBtn.style.cssText = `
      position: absolute;
      top: 50%;
      right: 12px;
      transform: translateY(-50%);
      width: 40px;
      height: 40px;
      border: none;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      color: white;
      border-radius: 8px;
      cursor: pointer;
      font-size: 20px;
      display: flex;
      align-items: center;
      justify-content: center;
      z-index: 999999;
      opacity: 0.95;
      transition: all 0.2s;
      box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
      pointer-events: auto;
    `;

    // Hover эффект
    viewBtn.addEventListener('mouseenter', function() {
      viewBtn.style.opacity = '1';
      viewBtn.style.transform = 'translateY(-50%) scale(1.08)';
    });

    viewBtn.addEventListener('mouseleave', function() {
      viewBtn.style.opacity = '0.95';
      viewBtn.style.transform = 'translateY(-50%) scale(1)';
    });

    let isRevealed = false;

    // НАЖАТИЕ кнопки - показать
    viewBtn.addEventListener('mousedown', function(e) {
      e.preventDefault();
      e.stopPropagation();
      
      if (!isRevealed) {
        isRevealed = true;
        iframe.style.filter = 'none';
        iframe.style.webkitFilter = 'none';
        viewBtn.textContent = '🙈';
        viewBtn.style.background = 'linear-gradient(135deg, #10b981 0%, #059669 100%)';
      }
    });

    // ОТПУСКАНИЕ кнопки - скрыть обратно
    viewBtn.addEventListener('mouseup', function(e) {
      e.preventDefault();
      e.stopPropagation();
      
      if (isRevealed) {
        isRevealed = false;
        iframe.style.setProperty('filter', 'blur(6px)', 'important');
        iframe.style.setProperty('-webkit-filter', 'blur(6px)', 'important');
        viewBtn.textContent = '👁️';
        viewBtn.style.background = 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)';
      }
    });

    // Если курсор ушел с кнопки при нажатии - тоже скрыть
    viewBtn.addEventListener('mouseleave', function(e) {
      if (isRevealed) {
        isRevealed = false;
        iframe.style.setProperty('filter', 'blur(6px)', 'important');
        iframe.style.setProperty('-webkit-filter', 'blur(6px)', 'important');
        viewBtn.textContent = '👁️';
        viewBtn.style.background = 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)';
      }
      viewBtn.style.opacity = '0.95';
      viewBtn.style.transform = 'translateY(-50%) scale(1)';
    });

    // Вставляем кнопку
    if (iframe.parentElement) {
      const parentStyle = window.getComputedStyle(iframe.parentElement);
      if (parentStyle.position === 'static') {
        iframe.parentElement.style.position = 'relative';
      }
      
      iframe.parentElement.appendChild(viewBtn);
    }
  }

  // Проверка - является ли поле полем для ввода карты
  function isCardInputField(input) {
    if (!input || input.tagName !== 'INPUT') return false;

    // ====== ПРОВЕРКА ИСКЛЮЧЕНИЙ (АБСОЛЮТНЫЙ ПРИОРИТЕТ!) ======
    // НЕ размываем поля с именем, адресом, email, телефоном, почтовым кодом
    const name = (input.name || '').toLowerCase();
    const id = (input.id || '').toLowerCase();
    const autoComplete = (input.autocomplete || '').toLowerCase();
    const placeholder = (input.placeholder || '').toLowerCase();
    const ariaLabel = (input.getAttribute('aria-label') || '').toLowerCase();
    
    const excludeKeywords = [
      'name', 'имя', 'fname', 'lname', 'firstname', 'lastname', 'cardholder',
      'address', 'адрес', 'street', 'улиц', 'line1', 'line2',
      'city', 'город', 'state', 'регион', 'область', 'province', 'region',
      'country', 'страна', 'county',
      'zip', 'postal', 'почт', 'индекс', 'postcode',
      'email', 'mail', 'phone', 'tel', 'mobile', 'телефон'
    ];
    
    const allFieldText = `${name} ${id} ${autoComplete} ${placeholder} ${ariaLabel}`;
    
    // Если поле содержит исключающие ключевые слова - НЕ размываем!
    if (excludeKeywords.some(keyword => allFieldText.includes(keyword))) {
      return false;
    }

    // ====== ПРИОРИТЕТ 0: ПРЯМАЯ ПРОВЕРКА НОМЕРА КАРТЫ ПО ЗНАЧЕНИЮ ======
    // ЭТО САМЫЙ ВЫСОКИЙ ПРИОРИТЕТ - проверяем ПЕРВЫМ!
    if (input.value && input.value.length > 0) {
      const digits = input.value.replace(/\D/g, '');
      // Если это точно номер карты (13-19 цифр) - возвращаем true СРАЗУ
      if (digits.length >= 13 && digits.length <= 19) {
        console.log('🔒 PassBlur: [isCardInputField] ✓✓✓ CARD NUMBER DETECTED BY VALUE! Digits:', digits.length, 'Value:', input.value.substring(0, 20) + '...');
        return true;
      }
    }

    // ====== ПРИОРИТЕТ 1: ПРОВЕРКА ЗНАЧЕНИЯ (САМОЕ ВАЖНОЕ!) ======
    // Если поле содержит данные карты - размываем ВСЕГДА, независимо от атрибутов!
    if (input.value && input.value.length > 0) {
      const value = input.value;
      // Убираем все нецифровые символы для проверки (включая префиксы типа "VISA")
      const digits = value.replace(/\D/g, '');
      const trimmedValue = value.trim();
      
      // НОМЕР КАРТЫ: 13-19 цифр - ЭТО ВСЕГДА КАРТА! (ПРИОРИТЕТ!)
      // Проверяем даже если есть пробелы, дефисы или префиксы типа "VISA", "MASTERCARD" и т.д.
      if (digits.length >= 13 && digits.length <= 19) {
        console.log('🔒 PassBlur: ✓✓✓ CARD NUMBER DETECTED! Digits:', digits.length, 'Value:', value.substring(0, 20) + '...');
        return true;
      }
      
      // ДОПОЛНИТЕЛЬНАЯ ПРОВЕРКА: номер карты может быть частично заполнен
      // Если есть 12+ цифр и поле имеет карточные атрибуты - это номер карты
      if (digits.length >= 12) {
        const name = (input.name || '').toLowerCase();
        const id = (input.id || '').toLowerCase();
        const placeholder = (input.placeholder || '').toLowerCase();
        const autoComplete = (input.autocomplete || input.getAttribute('autocomplete') || '').toLowerCase();
        const allText = `${name} ${id} ${placeholder} ${autoComplete}`;
        
        // Проверяем наличие карточных ключевых слов
        if (allText.includes('card') || allText.includes('credit') || allText.includes('debit') || 
            allText.includes('number') || allText.includes('cc-') || allText.includes('номер')) {
          console.log('🔒 PassBlur: ✓✓✓ CARD NUMBER DETECTED (partial + attributes)! Digits:', digits.length);
          return true;
        }
      }
      
      // CVV/CVC: 3-4 цифры (только если поле короткое)
      if (digits.length >= 3 && digits.length <= 4 && trimmedValue.length <= 5) {
        console.log('🔒 PassBlur: ✓✓✓ CVV/CVC DETECTED!');
        return true;
      }
      
      // ДАТА ИСТЕЧЕНИЯ: XX/XX или XX/XXXX
      if (/^\d{2}\s*\/\s*\d{2,4}$/.test(trimmedValue)) {
        console.log('🔒 PassBlur: ✓✓✓ EXPIRY DATE DETECTED!');
        return true;
      }
    }

    // ====== ПРИОРИТЕТ 2: ПРОВЕРКА АТРИБУТОВ ======
    const name = (input.name || '').toLowerCase();
    const id = (input.id || '').toLowerCase();
    const placeholder = (input.placeholder || '').toLowerCase();
    const autoCompleteAttr = input.autocomplete || input.getAttribute('autocomplete');
    const autoComplete = (autoCompleteAttr || '').toLowerCase();
    const ariaLabelAttr = input.getAttribute('aria-label');
    const ariaLabel = (ariaLabelAttr || '').toLowerCase();
    const dataStripeAttr = input.getAttribute('data-stripe');
    const dataStripe = (dataStripeAttr || '').toLowerCase();
    const classNameAttr = input.className;
    const className = (classNameAttr || '').toLowerCase();
    const typeAttr = input.type;
    const type = (typeAttr || '').toLowerCase();
    const inputModeAttr = input.inputMode || input.getAttribute('inputmode');
    const inputMode = (inputModeAttr || '').toLowerCase();

    // Проверяем родительские элементы (включая Stripe контейнеры)
    let parentText = '';
    let parent = input.parentElement;
    for (let i = 0; i < 5 && parent; i++) { // Увеличено до 5 уровней для Stripe
      parentText += ' ' + (parent.className || '').toLowerCase();
      parentText += ' ' + (parent.id || '').toLowerCase();
      parent = parent.parentElement;
    }

    // СПЕЦИАЛЬНАЯ ПРОВЕРКА: Stripe элементы
    // Stripe использует классы типа _PrivateStripeElement-input
    if (className.includes('privatestripeelement') || className.includes('stripe') || 
        parentText.includes('privatestripeelement') || parentText.includes('stripe')) {
      // Если это Stripe элемент и содержит номер карты - размываем
      if (input.value && input.value.length > 0) {
        const digits = input.value.replace(/\D/g, '');
        if (digits.length >= 13 && digits.length <= 19) {
          console.log('🔒 PassBlur: ✓✓✓ STRIPE CARD NUMBER DETECTED! Digits:', digits.length);
          return true;
        }
      }
      // Также проверяем по атрибутам Stripe
      if (dataStripe.includes('number') || dataStripe.includes('card') || 
          autoComplete.includes('cc-') || autoComplete.includes('card')) {
        console.log('🔒 PassBlur: ✓✓✓ STRIPE CARD FIELD DETECTED (by attributes)!');
        return true;
      }
    }

    // РАСШИРЕННЫЕ ключевые слова для полей карт
    const cardKeywords = [
      'card', 'карт', 'credit', 'debit',
      'cc-number', 'cardnumber', 'card-number', 'card_number',
      'номер', 'cvv', 'cvc', 'cvc2', 'cvv2', 'security', 'code',
      'expir', 'expire', 'exp', 'expiry', 'expiration',
      'payment', 'billing'
    ];

    // Ключевые слова специально для имени держателя карты
    const cardholderNameKeywords = [
      'cardholder', 'namecard', 'card-name', 'card_name',
      'holder-name', 'holder_name', 'cardholder-name', 'cardholder_name'
    ];

    // ВАЖНО: ИСКЛЮЧЕНИЯ - НЕ размываем поля имени, адреса, email, телефона
    // Эти поля могут находиться в форме оплаты, но не должны размываться
    const excludeKeywords = [
      'name', 'fname', 'lname', 'firstname', 'lastname', 'fullname',
      'address', 'street', 'city', 'state', 'zip', 'postal', 'country', 'region',
      'email', 'phone', 'tel', 'mobile',
      'имя', 'фамилия', 'адрес', 'город', 'область', 'индекс', 'телефон'
    ];
    
    // Проверяем, не является ли это исключенным полем
    const inputAttrs = `${name} ${id} ${placeholder} ${autoComplete} ${ariaLabel}`;
    const isExcludedField = excludeKeywords.some(keyword => inputAttrs.includes(keyword));
    
    if (isExcludedField) {
      console.log('🔒 PassBlur: Field excluded (name/address/contact):', inputAttrs.substring(0, 50));
      return false; // НЕ размываем это поле
    }
    
    // Проверяем все атрибуты ВКЛЮЧАЯ родителей
    const allText = `${name} ${id} ${placeholder} ${autoComplete} ${ariaLabel} ${dataStripe} ${className} ${parentText}`;
    
    // Проверяем по ключевым словам для карт
    if (cardKeywords.some(keyword => allText.includes(keyword))) {
      // Дополнительная проверка: если это НЕ поле с числовым типом и НЕ содержит данных карты - не размываем
      if (!input.value || input.value.length === 0) {
        // Пустое поле - размываем только если это явно поле карты по атрибутам
        const directCardAttrs = `${name} ${id} ${autoComplete}`;
        if (!directCardAttrs.includes('card') && !directCardAttrs.includes('cc-') && !directCardAttrs.includes('cvv') && !directCardAttrs.includes('cvc')) {
          console.log('🔒 PassBlur: Empty field without direct card attributes, skipping');
          return false;
        }
      }
      return true;
    }

    // ИМЯ ДЕРЖАТЕЛЯ: НЕ размываем поля имени - они уже исключены выше
    // Эта проверка удалена, так как поля имени теперь в списке исключений

    // Проверка по типу поля - numeric часто для карт
    // НО: приоритет отдаем полям с карточными атрибутами или значениями
    if (type === 'tel' || type === 'number' || inputMode === 'numeric' || inputMode === 'decimal') {
      // Если поле уже содержит цифры - проверяем, это номер карты?
      if (input.value && input.value.length > 0) {
      const digits = input.value.replace(/\D/g, '');
        // Если есть 12+ цифр - это скорее всего номер карты
        if (digits.length >= 12) {
          console.log('🔒 PassBlur: ✓✓✓ CARD NUMBER DETECTED (by type + digits)! Digits:', digits.length);
          return true;
        }
      }
      // Если поле имеет карточные атрибуты - размываем даже без значения
      if (cardKeywords.some(keyword => allText.includes(keyword))) {
        return true;
      }
      // Иначе не размываем - может быть обычное числовое поле
      return false;
    }

    // Проверка autocomplete атрибутов - ПРИОРИТЕТ!
    // Стандартные autocomplete значения для карт
    const cardAutocompleteValues = [
      'cc-number', 'cc-num', 'ccnumber', 'card-number', 'cardnumber',
      'cc-csc', 'cc-cvc', 'cvv', 'cvc', 'security-code',
      'cc-exp', 'cc-exp-month', 'cc-exp-year', 'expiry', 'expiration',
      'cc-name', 'cardholder-name', 'cardholder'
    ];
    
    if (autoComplete && cardAutocompleteValues.some(val => autoComplete.includes(val))) {
      console.log('🔒 PassBlur: ✓✓✓ CARD FIELD DETECTED (by autocomplete):', autoComplete);
      return true;
    }
    
    // Также проверяем общие паттерны
    if (autoComplete.includes('cc-') || autoComplete.includes('card')) {
      return true;
    }

    // ДОПОЛНИТЕЛЬНАЯ ПРОВЕРКА: если поле имеет карточные атрибуты И содержит цифры
    if (cardKeywords.some(keyword => allText.includes(keyword)) && input.value && input.value.length > 0) {
      const digits = input.value.replace(/\D/g, '');
      // Если есть 12+ цифр - это номер карты
      if (digits.length >= 12) {
        console.log('🔒 PassBlur: ✓✓✓ CARD NUMBER DETECTED (by attributes + digits)! Digits:', digits.length);
        return true;
      }
    }

    return false;
  }

  // Перехват кликов по кнопкам которые могут открывать модалки
  function setupClickInterceptor() {
    document.addEventListener('click', function(e) {
      if (!isEnabled) return;
      
      const target = e.target;
      
      // Проверяем клики по кнопкам/ссылкам которые могут открывать формы оплаты
      if (target.matches && (
        target.matches('button') || 
        target.matches('[role="button"]') ||
        target.matches('a') ||
        target.closest('button') ||
        target.closest('[role="button"]')
      )) {
        console.log('🔒 PassBlur: Button clicked - checking for new payment fields...');
        
        // Запускаем агрессивную проверку всех полей - НЕ только input полей!
        setTimeout(() => {
          if (isEnabled) checkForCardFields();
        }, 10);
        setTimeout(() => {
          if (isEnabled) checkForCardFields();
        }, 50);
        setTimeout(() => {
          if (isEnabled) checkForCardFields();
        }, 150);
        setTimeout(() => {
          if (isEnabled) checkForCardFields();
        }, 300);
        setTimeout(() => {
          if (isEnabled) checkForCardFields();
        }, 500);
      }
    }, true); // Используем capture phase для более раннего срабатывания
  }

  // Агрессивная проверка всех полей на наличие данных карт
  function checkForCardFields() {
    console.log('🔒 PassBlur: Running aggressive card field check...');
    const allInputs = document.querySelectorAll('input');
    console.log('🔒 PassBlur: Found', allInputs.length, 'input elements');
    
    let foundCount = 0;
    allInputs.forEach(input => {
      if (input.value && input.value.length > 0 && !input.classList.contains('passblur-input-processed')) {
        if (isCardInputField(input)) {
          console.log('🔒 PassBlur: ✓✓✓ CARD FIELD FOUND - applying blur!');
          applyBlurToFilledInput(input);
          foundCount++;
        }
      }
    });
    
    if (foundCount > 0) {
      console.log('🔒 PassBlur: Blurred', foundCount, 'card fields');
    }
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

      // УМНАЯ ПРОВЕРКА: это чувствительные данные?
      if (isLikelySensitiveData(value)) {
        processInputField(input);
      }
    });
  }

  // Проверка - является ли это телефонным номером (не просто цифрами)
  function isValidPhoneNumber(text) {
    // Подсчитываем количество цифр
    const digits = text.replace(/\D/g, '');
    
    // Минимум 10 цифр для телефона
    if (digits.length < 10) {
      return false;
    }
    
    // Проверяем наличие форматирования (скобки, тире, пробелы, +)
    const hasFormatting = /[\(\)\-\s\+]/.test(text);
    
    // Если есть + в начале - это телефон
    if (text.trim().startsWith('+')) {
      return true;
    }
    
    // Если начинается с 8 или 7 и есть форматирование - российский номер
    if (/^[87]/.test(digits) && hasFormatting) {
      return true;
    }
    
    // Если есть скобки (XXX) - скорее всего телефон
    if (/\(\d{3}\)/.test(text)) {
      return true;
    }
    
    // Если много цифр подряд без форматирования - вероятно НЕ телефон
    if (digits.length > 10 && !hasFormatting) {
      return false;
    }
    
    return hasFormatting && digits.length >= 10;
  }

  // Умное определение - содержит ли строка чувствительные данные
  function isLikelySensitiveData(value) {
    // Минимальная длина проверки
    if (value.length < 5) {
      return false;
    }

    // Получаем активные паттерны на основе фильтров
    const activePatterns = getActivePatterns();

    // Проверяем на конкретные паттерны
    for (const [keyType, pattern] of Object.entries(activePatterns)) {
      // Сбрасываем lastIndex для глобальных regex
      pattern.lastIndex = 0;
      
      if (pattern.test(value)) {
        const matches = value.match(pattern);
        if (matches && matches[0]) {
          const matchedText = matches[0];
          
          // Дополнительная проверка для телефонов
          if (keyType.includes('Phone')) {
            if (!isValidPhoneNumber(matchedText)) {
              continue; // Пропускаем, если это не телефон
            }
          }
          
          // Разные минимальные длины для разных типов
          const minLength = (keyType.includes('Email') || keyType.includes('Phone') || keyType.includes('SSN') || keyType.includes('Card')) ? 5 : 20;
          
          if (matchedText.length >= minLength) {
            return true;
          }
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
    
    // Еще одна проверка - это действительно чувствительные данные?
    if (!isLikelySensitiveData(value)) {
      input.classList.remove('passblur-input-processed'); // Снимаем метку
      processingElements.delete(input); // Удаляем из Set
      return;
    }
    
    let keyType = 'Unknown';
    const activePatterns = getActivePatterns();
    
    for (const [type, pattern] of Object.entries(activePatterns)) {
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
        if (innerValue.length >= 5 && isLikelySensitiveData(innerValue)) {
          // Нашли реальный элемент с чувствительными данными
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

  // Получение активных паттернов на основе фильтров
  function getActivePatterns() {
    let activePatterns = {};
    
    Object.keys(detectionFilters).forEach(filterKey => {
      if (detectionFilters[filterKey] && DETECTION_PATTERNS[filterKey]) {
        activePatterns = { ...activePatterns, ...DETECTION_PATTERNS[filterKey] };
      }
    });
    
    return activePatterns;
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

    // Получаем активные паттерны на основе фильтров
    const activePatterns = getActivePatterns();

    // Проверяем текст на все активные паттерны
    for (const [keyType, pattern] of Object.entries(activePatterns)) {
      pattern.lastIndex = 0; // Сброс для глобальных regex
      const matches = [...text.matchAll(pattern)];
      matches.forEach(match => {
        const matchedText = match[0];
        
        // Дополнительная проверка для телефонов
        if (keyType.includes('Phone')) {
          if (!isValidPhoneNumber(matchedText)) {
            return; // Пропускаем, если это не телефон
          }
        }
        
        // Проверка минимальной длины в зависимости от типа
        const minLength = (keyType.includes('Email') || keyType.includes('Phone') || keyType.includes('SSN')) ? 5 : 20;
        
        if (matchedText.length >= minLength) {
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
    if (isLikelySensitiveData(value)) {
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
        console.log('🔒 PassBlur: Manual rescan triggered from popup');
        removeAllBlurs();
        scanPage();
        checkForCardFields(); // Также проверяем карточные поля!
        sendResponse({ success: true, count: blurredElements.size });
      } else if (request.action === 'getStatus') {
        sendResponse({ 
          enabled: isEnabled, 
          count: blurredElements.size 
        });
      } else if (request.action === 'updateFilters') {
        // Обновляем фильтры
        if (request.filters) {
          detectionFilters = { ...detectionFilters, ...request.filters };
          
          // Пересканируем страницу с новыми фильтрами
          removeAllBlurs();
          if (isEnabled) {
            scanPage();
            checkForCardFields(); // Также проверяем карточные поля!
          }
          
          sendResponse({ success: true, count: blurredElements.size });
        } else {
          sendResponse({ success: false, error: 'No filters provided' });
        }
      }
      return true;
    });
  }

  // ГЛОБАЛЬНАЯ функция для ручного запуска из консоли
  window.PassBlurManualCheck = function() {
    console.log('🔒 PassBlur: ===== MANUAL CHECK STARTED =====');
    checkForCardFields();
    console.log('🔒 PassBlur: ===== MANUAL CHECK COMPLETED =====');
  };

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

