import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.svm import SVC  # Импорт класса SVM
from sklearn.preprocessing import LabelEncoder, OneHotEncoder
from sklearn.metrics import roc_curve, auc
import matplotlib.pyplot as plt

# Загрузка данных из CSV-файла
data = pd.read_csv(r'D:\CIC-DDoS2019 Dataset\cicddos2019_dataset.csv')

# Удаление строк с отсутствующими значениями в целевой переменной
data.dropna(subset=['Label'], inplace=True)

# Общее количество строк в наборе данных
total_rows = data.shape[0]
print("Общее количество строк в наборе данных:", total_rows)

# Выбор целевой переменной и признаков
y = data['Label']  # Целевая переменная - метка атаки или нормального трафика
X = data.drop(['Label'], axis=1)  # Признаки - характеристики сетевого трафика

# Преобразование категориальных признаков в числовые с помощью One-Hot Encoding
encoder = OneHotEncoder()
X_encoded = encoder.fit_transform(X)

# Разделение данных на обучающую и тестовую выборки в соотношении 70:30
X_train, X_test, y_train, y_test = train_test_split(X_encoded, y, test_size=0.3, random_state=42)

# Кодирование меток классов
le = LabelEncoder()
y_train = le.fit_transform(y_train)
y_test = le.transform(y_test)

# Классы, которые будут в тестовой выборке
test_classes = np.unique(y_test)
# Обратное преобразование меток классов в текстовый формат
test_classes_text = le.inverse_transform(test_classes)
print("Классы, которые будут в тестовой выборке:", test_classes_text)

# Обучение модели SVM с включенной оценкой вероятности
svm = SVC(kernel='poly', probability=True)  # Инициализируем модель SVM с оценкой вероятности
svm.fit(X_train, y_train)  # Обучаем модель на обучающих данных

# Получение прогнозов на тестовых данных
y_pred_proba = svm.predict_proba(X_test)

# Вычисление ROC-кривой и площади под кривой (AUC) для каждого класса
fpr = dict()
tpr = dict()
roc_auc = dict()
for i in range(len(test_classes)):
    fpr[i], tpr[i], _ = roc_curve(y_test, y_pred_proba[:, i], pos_label=i)
    roc_auc[i] = auc(fpr[i], tpr[i])

# Построение ROC-кривой
plt.figure(figsize=(8, 6))
for i in range(len(test_classes)):
    plt.plot(fpr[i], tpr[i], label='ROC-кривая (класс {}) (AUC = {:.2f})'.format(test_classes_text[i], roc_auc[i]))

plt.plot([0, 1], [0, 1], 'k--')  # случайная кривая классификатора
plt.xlim([0.0, 1.0])
plt.ylim([0.0, 1.05])
plt.xlabel('Ложноположительная оценка')
plt.ylabel('Истинно положительная оценка')
plt.title('ROC-кривая')
plt.legend(loc="lower right")
plt.show()
