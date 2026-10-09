const tailState = document.getElementById("tail-state");
const tailRows = document.getElementById("tail-rows");
const source = new EventSource(tailRows.dataset.streamUrl);

source.onopen = () => {
  tailState.textContent = "Live";
};
source.onerror = () => {
  tailState.textContent = "Reconnecting…";
};
source.onmessage = (message) => {
  const event = JSON.parse(message.data);
  const stayAtBottom = tailRows.scrollHeight - tailRows.scrollTop <= tailRows.clientHeight + 40;
  const line = document.createElement("div");
  line.className = "terminal-line";
  const meta = document.createElement("span");
  meta.className = "terminal-meta";
  const eventType = event.event_type === "log" ? "" : "[" + event.event_type + "] ";
  meta.textContent = `${event.ts} [${event.device}] [${event.level || ""}] [${event.component || ""}] ${eventType}`;
  const messageText = document.createElement("span");
  messageText.className = "terminal-message";
  messageText.textContent = event.clean;
  line.append(meta, messageText);
  tailRows.appendChild(line);
  while (tailRows.children.length > 500) tailRows.firstElementChild.remove();
  if (stayAtBottom) tailRows.scrollTop = tailRows.scrollHeight;
};

tailRows.scrollTop = tailRows.scrollHeight;
