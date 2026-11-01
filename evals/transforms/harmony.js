const FINAL_MARKER = "<|channel|>final<|message|>";
const RETURN_MARKER = "<|return|>";

function stripTrailingMarkerResidue(text) {
  let value = String(text ?? "");
  value = value.replace(/(<\|im_end\|>|<\|eot_id\|>|<\/s>)\s*$/g, "");

  const trimmedRight = value.replace(/\s+$/g, "");
  const trailingWhitespace = value.slice(trimmedRight.length);
  value = trimmedRight;

  if (value.endsWith(RETURN_MARKER)) {
    value = value.slice(0, -RETURN_MARKER.length);
  } else {
    for (let length = RETURN_MARKER.length - 1; length > 0; length -= 1) {
      if (value.endsWith(RETURN_MARKER.slice(0, length))) {
        value = value.slice(0, -length);
        break;
      }
    }
  }

  return value.replace(/\s+$/g, "") + trailingWhitespace.replace(/\S/g, "");
}

export default function harmonyTransform(output) {
  if (output !== null && typeof output === "object") {
    if (Array.isArray(output)) {
      return output;
    }
    if (typeof output.content === "string") {
      return { ...output, content: harmonyTransform(output.content) };
    }
    return output;
  }
  const text = String(output ?? "");
  const finalStart = text.lastIndexOf(FINAL_MARKER);

  if (finalStart === -1) {
    if (text.includes("<|channel|>") || text.includes("<|message|>")) {
      return "";
    }
    return stripTrailingMarkerResidue(text).trim();
  }

  const contentStart = finalStart + FINAL_MARKER.length;
  const returnStart = text.indexOf(RETURN_MARKER, contentStart);
  const finalText =
    returnStart === -1 ? text.slice(contentStart) : text.slice(contentStart, returnStart);
  return stripTrailingMarkerResidue(finalText).trim();
}
