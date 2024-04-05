import pandas as pd

# Загрузка датасета
data = pd.read_csv(r'D:\CIC-DDoS2019 Dataset\cicddos2019_dataset.csv')

# Вывод общей информации о датасете
print("Общая информация о датасете:")
print(data.info())

# Вывод первых нескольки строк датасета
print("\nПервые несколько строк датасета:")
print(data.head())

# Статистика по числовым признакам
print("\nСтатистика по числовым признакам:")
print(data.describe())

# Уникальные значения в категориальных столбцах
print("\nУникальные значения в категориальных столбцах:")
for column in data.select_dtypes(include=['object']).columns:
    print(f"{column}: {data[column].unique()}")

# Проверка наличия пропущенных значений
print("\nПроверка наличия пропущенных значений:")
print(data.isnull().sum())

# Проверка наличия дубликатов
print("\nПроверка наличия дубликатов:")
print("Количество дубликатов:", data.duplicated().sum())

# Проверка баланса классов (если есть целевая переменная)
if 'Label' in data.columns:
    print("\nБаланс классов:")
    print(data['Label'].value_counts())

# Подробная информация о каждом столбце
print("\nИнформация о каждом столбце:")
print(data.info(verbose=True))

















