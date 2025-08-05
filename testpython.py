from transformers import BertTokenizer, BertForQuestionAnswering
import torch

# Load pre-trained model and tokenizer
model_name = 'bert-base-uncased'
tokenizer = BertTokenizer.from_pretrained(model_name)
model = BertForQuestionAnswering.from_pretrained(model_name)

def answer_question(document, question):
    # Tokenize input
    inputs = tokenizer.encode_plus(question, document, add_special_tokens=True, return_tensors='pt')

    # Perform inference
    with torch.no_grad():
        start_scores, end_scores = model(**inputs)

    # Get the most likely answer
    start_index = torch.argmax(start_scores)
    end_index = torch.argmax(end_scores)

    # Convert token indices to actual tokens
    tokens = tokenizer.convert_ids_to_tokens(inputs['input_ids'][0])
    answer = tokenizer.convert_tokens_to_string(tokens[start_index:end_index+1])

    return answer

# Example usage
document = "This is a sample document. It contains some text that we can use for testing our question answering system."
question = "What can we use for testing our system?"

answer = answer_question(document, question)
print("Answer:", answer)
