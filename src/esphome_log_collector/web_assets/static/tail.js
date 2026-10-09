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
  const row = document.createElement("tr");
  for (const value of [event.ts, event.device, event.level || "", event.component || ""]) {
    const cell = document.createElement("td");
    cell.textContent = value;
    row.appendChild(cell);
  }
  const typeCell = document.createElement("td");
  typeCell.textContent = event.event_type === "log" ? "" : "[" + event.event_type + "]";
  row.appendChild(typeCell);
  const lineCell = document.createElement("td");
  lineCell.className = "m";
  lineCell.textContent = event.clean;
  row.appendChild(lineCell);
  const stayAtBottom = window.innerHeight + window.scrollY >= document.body.scrollHeight - 40;
  tailRows.appendChild(row);
  while (tailRows.rows.length > 500) tailRows.deleteRow(0);
  if (stayAtBottom) window.scrollTo(0, document.body.scrollHeight);
};

window.scrollTo(0, document.body.scrollHeight);
