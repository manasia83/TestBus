from transformers import BertTokenizer

def answer_question(document, question):
    tokenizer = BertTokenizer.from_pretrained('bert-base-uncased')

    # Tokenize input
    inputs = tokenizer.encode_plus(question, document, add_special_tokens=True, return_tensors='pt')

    # Convert token indices to actual tokens
    tokens = tokenizer.convert_ids_to_tokens(inputs['input_ids'][0])
    answer = tokenizer.convert_tokens_to_string(tokens[1:-1])  # Exclude special tokens [CLS] and [SEP]

    return answer

# Example usage
document = "This is a sample document. It contains some text that we can use for testing our question answering system."
question = "What can we use for testing our system?"

answer = answer_question(document, question)

# Write the answer to a file
with open('answer.txt', 'w') as file:
    file.write(answer)
