// Помощник для вывода сообщений в консоль.
const приветствие = "Привет, мир!";
const предупреждение = "Внимание: проверьте настройки";

function logMessage(message) {
    console.log(message);
    return message;
}

logMessage(приветствие);
logMessage(предупреждение);
